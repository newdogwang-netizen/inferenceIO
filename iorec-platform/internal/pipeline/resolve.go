package pipeline

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/jobs"
)

// Evidence weights (platform/06 §3).
const (
	confExplicit    = 1.0
	confPrefixChain = 0.95
	confResponseID  = 0.95
	confToolCallID  = 0.9
	confInputHash   = 0.9
	confFingerprint = 0.6
	confTemporalPID = 0.4
	minRelationConf = 0.6
	conflictMargin  = 0.15
	retryWindow     = 10 * time.Minute
	adjacencyWindow = 5 * time.Minute
)

type evidence struct {
	Kind   string        `json:"kind"`
	Weight float64       `json:"weight"`
	Refs   []EvidenceRef `json:"refs,omitempty"`
	Note   string        `json:"note,omitempty"`
}

type attemptRow struct {
	ID, Recording  string
	InferenceID    string // explicit raw ID, or canonicalized cross-source ID
	Source         string
	PID            int
	StartedAt      time.Time
	InputHash      string
	Fingerprint    string
	Host           string
	Terminal       string
	FirstSeq, Last int64
	Norm           *Normalized
	Correlation    *evidence
}

type inferenceNode struct {
	ID          string
	Recording   string
	Observed    bool
	PID         int
	At          time.Time
	InputHash   string
	Fingerprint string
	TaskID      string // explicit native task id or resolved capture-task key
	SessionID   string // explicit native
	TurnID      string
	Norm        *Normalized
	Request     json.RawMessage
	Response    json.RawMessage
	Usage       json.RawMessage
	Attempts    []*attemptRow
	Evidence    []EvidenceRef
	Model       string
	APIMode     string
	// resolved
	prev       *inferenceNode
	prevEv     evidence
	sessionKey string
	turnIndex  int
	conflict   bool
}

// Resolve rebuilds sessions and relations for a capture run (platform/06 §4).
func (d *Deps) Resolve(ctx context.Context, j *jobs.Job) error {
	run := runIDOf(j)
	if run == "" {
		return fmt.Errorf("resolve: no capture_run_id")
	}
	// 1. facts
	attempts, err := d.loadAttempts(ctx, run)
	if err != nil {
		return err
	}
	observed, err := d.loadObservedInferences(ctx, run)
	if err != nil {
		return err
	}
	correlations, sessionCorrelations, err := d.loadInferenceCorrelations(ctx, run)
	if err != nil {
		return err
	}
	nodes := map[string]*inferenceNode{}
	for _, o := range observed {
		nodes[o.ID] = o
	}
	// A recorder correlation maps an observer-native inference onto the
	// transport inference already used by attempt links and user-facing URLs.
	// Merge the observer projection into that canonical node without deleting
	// any immutable raw event evidence.
	for alias, correlation := range correlations {
		source := nodes[alias]
		target := nodes[correlation.Canonical]
		if source == nil {
			continue
		}
		if target == nil {
			delete(nodes, alias)
			source.ID = correlation.Canonical
			target = source
			nodes[target.ID] = target
		} else if source != target {
			mergeInferenceNode(target, source)
			delete(nodes, alias)
		}
		target.Evidence = append(target.Evidence, correlation.Evidence.Refs...)
	}
	for canonical, correlation := range sessionCorrelations {
		node := nodes[canonical]
		if node == nil {
			node = &inferenceNode{ID: canonical, Recording: correlation.Recording, At: correlation.At}
			nodes[canonical] = node
		}
		if node.TaskID == "" {
			node.TaskID = correlation.TaskID
		} else if correlation.TaskID != "" && node.TaskID != correlation.TaskID {
			node.conflict = true
		}
		if node.SessionID == "" {
			node.SessionID = correlation.SessionID
		} else if correlation.SessionID != "" && node.SessionID != correlation.SessionID {
			node.conflict = true
		}
		if node.TurnID == "" {
			node.TurnID = correlation.TurnID
		} else if correlation.TurnID != "" && node.TurnID != correlation.TurnID {
			node.conflict = true
		}
		node.Evidence = append(node.Evidence, correlation.Evidence.Refs...)
	}
	// 2. attempt -> inference
	var unbound []*attemptRow
	for _, a := range attempts {
		if correlation, ok := correlations[a.InferenceID]; ok {
			a.InferenceID = correlation.Canonical
			ev := correlation.Evidence
			a.Correlation = &ev
		}
		if a.InferenceID != "" {
			n := nodes[a.InferenceID]
			if n == nil {
				n = &inferenceNode{ID: a.InferenceID, Recording: a.Recording, PID: a.PID, At: a.StartedAt, InputHash: a.InputHash, Fingerprint: a.Fingerprint, Norm: a.Norm}
				nodes[n.ID] = n
			}
			n.Attempts = append(n.Attempts, a)
			continue
		}
		unbound = append(unbound, a)
	}
	sort.Slice(unbound, func(i, k int) bool { return unbound[i].StartedAt.Before(unbound[k].StartedAt) })
	// bind to observed hook inferences by input hash
	for _, a := range unbound {
		var bound bool
		if a.InputHash != "" {
			for _, n := range nodes {
				if n.Observed && n.InputHash == a.InputHash && n.PID == a.PID && absDur(n.At, a.StartedAt) < retryWindow {
					n.Attempts = append(n.Attempts, a)
					bound = true
					break
				}
			}
		}
		if bound {
			continue
		}
		// group with previous inferred inference of same pid+input_hash within retry window
		var target *inferenceNode
		if a.InputHash != "" {
			for _, n := range nodes {
				if !n.Observed && n.InputHash == a.InputHash && n.PID == a.PID && absDur(n.At, a.StartedAt) < retryWindow {
					target = n
					break
				}
			}
		}
		if target == nil {
			target = &inferenceNode{ID: "inf:" + a.ID, Recording: a.Recording, PID: a.PID, At: a.StartedAt, InputHash: a.InputHash, Fingerprint: a.Fingerprint, Norm: a.Norm}
			nodes[target.ID] = target
		}
		target.Attempts = append(target.Attempts, a)
	}
	// fill node fields from attempts
	list := make([]*inferenceNode, 0, len(nodes))
	for _, n := range nodes {
		sort.Slice(n.Attempts, func(i, k int) bool { return n.Attempts[i].StartedAt.Before(n.Attempts[k].StartedAt) })
		if len(n.Attempts) > 0 {
			a0 := n.Attempts[0]
			if n.At.IsZero() || a0.StartedAt.Before(n.At) {
				n.At = a0.StartedAt
			}
			best, bestScore := n.Norm, normalizedProjectionScore(n.Norm, "")
			for _, attempt := range n.Attempts {
				if score := normalizedProjectionScore(attempt.Norm, attempt.Terminal); score >= bestScore {
					best, bestScore = attempt.Norm, score
				}
			}
			n.Norm = best
			if n.PID == 0 {
				n.PID = a0.PID
			}
			for _, a := range n.Attempts {
				n.Evidence = append(n.Evidence, EvidenceRef{RecordingID: a.Recording, FirstSeq: a.FirstSeq, LastSeq: a.Last})
			}
		}
		if n.Norm != nil {
			n.Model, n.APIMode = n.Norm.Model, n.Norm.APIMode
			n.InputHash, n.Fingerprint = n.Norm.InputHash, n.Norm.Fingerprint
		}
		list = append(list, n)
	}
	sort.Slice(list, func(i, k int) bool { return list[i].At.Before(list[k].At) })
	// 3. link inferences
	for i, cur := range list {
		if cur.Norm == nil || cur.Norm.BodyUnavailable {
			continue
		}
		type cand struct {
			n  *inferenceNode
			ev evidence
		}
		var cands []cand
		for k := i - 1; k >= 0 && k >= i-200; k-- {
			prev := list[k]
			if prev.Norm == nil || prev.Norm.BodyUnavailable {
				continue
			}
			if ev, ok := linkEvidence(prev, cur); ok {
				cands = append(cands, cand{prev, ev})
			}
		}
		if len(cands) == 0 {
			continue
		}
		// strongest evidence first; among equals prefer the longest shared prefix (closest predecessor)
		sort.Slice(cands, func(a, b int) bool {
			if cands[a].ev.Weight != cands[b].ev.Weight {
				return cands[a].ev.Weight > cands[b].ev.Weight
			}
			return len(cands[a].n.Norm.MessageHashes) > len(cands[b].n.Norm.MessageHashes)
		})
		best := cands[0]
		if best.ev.Weight < minRelationConf {
			continue
		}
		// conflict: a second candidate nearly as strong that is not simply an ancestor of the best one
		// (every earlier inference of the same conversation is a prefix of the current one). Explicit
		// session ids from hooks settle attribution and never yield a conflict.
		if cur.SessionID == "" {
			for _, c := range cands[1:] {
				if c.n == best.n || best.ev.Weight-c.ev.Weight >= conflictMargin {
					break
				}
				if !isPrefix(c.n.Norm.MessageHashes, best.n.Norm.MessageHashes) {
					cur.conflict = true
					break
				}
			}
		}
		cur.prev, cur.prevEv = best.n, best.ev
	}
	// 4. sessions: chains via prev pointers; explicit native session ids override
	nativeSessions := map[string]string{}
	for _, n := range list {
		if n.SessionID != "" {
			nativeSessions[SessionKey(run, n.SessionID)] = n.SessionID
		}
	}
	root := func(n *inferenceNode) *inferenceNode {
		for n.prev != nil && !n.conflict {
			n = n.prev
		}
		return n
	}
	for _, n := range list {
		if n.SessionID != "" {
			n.sessionKey = SessionKey(run, n.SessionID)
			continue
		}
		r := root(n)
		// inherit native id along the chain if any member has one
		key := ""
		for m := n; m != nil; m = m.prev {
			if m.SessionID != "" {
				key = SessionKey(run, m.SessionID)
				break
			}
			if m.conflict {
				break
			}
		}
		if key == "" {
			key = "sess:" + r.ID // r.ID is already "inf:<run>~<attempt>" for inferred inferences
		}
		n.sessionKey = key
	}
	// turns: new user message beyond previous input => new turn
	turnsBySession := map[string][]map[string]any{}
	bySession := map[string][]*inferenceNode{}
	for _, n := range list {
		bySession[n.sessionKey] = append(bySession[n.sessionKey], n)
	}
	for key, ns := range bySession {
		sort.Slice(ns, func(i, k int) bool { return ns[i].At.Before(ns[k].At) })
		turn := 0
		var explicitTurns = map[string]int{}
		for i, n := range ns {
			newTurn := i == 0
			if n.TurnID != "" {
				if idx, ok := explicitTurns[n.TurnID]; ok {
					n.turnIndex = idx
					continue
				}
				newTurn = true
			} else if i > 0 && n.prev != nil && n.Norm != nil && n.prev.Norm != nil {
				pl := len(n.prev.Norm.Messages)
				for k := pl; k < len(n.Norm.Messages); k++ {
					if n.Norm.Messages[k].Role == "user" {
						newTurn = true
						break
					}
				}
			} else if i > 0 && n.prev == nil {
				newTurn = true
			}
			if newTurn {
				turn++
				if n.TurnID != "" {
					explicitTurns[n.TurnID] = turn
				}
			}
			n.turnIndex = turn
		}
		var turns []map[string]any
		byTurn := map[int][]*inferenceNode{}
		var order []int
		for _, n := range ns {
			if _, ok := byTurn[n.turnIndex]; !ok {
				order = append(order, n.turnIndex)
			}
			byTurn[n.turnIndex] = append(byTurn[n.turnIndex], n)
		}
		for _, ti := range order {
			members := byTurn[ti]
			ids := make([]string, 0, len(members))
			tid := fmt.Sprintf("%s#t%d", key, ti)
			for _, m := range members {
				ids = append(ids, m.ID)
				if m.TurnID != "" {
					tid = m.TurnID
				}
			}
			turns = append(turns, map[string]any{"turn_id": tid, "index": ti, "started_at": members[0].At, "ended_at": members[len(members)-1].At, "inference_ids": ids})
		}
		turnsBySession[key] = turns
	}
	// 5. subagent parent_of (explicit from hooks; inferred by nesting + different fingerprint)
	subEvents, err := d.loadSubagentEvents(ctx, run)
	if err != nil {
		return err
	}
	parentOf := map[string]struct {
		parent string
		ev     evidence
	}{}
	for _, se := range subEvents {
		if se.child != "" && se.parent != "" {
			parentOf[SessionKey(run, se.child)] = struct {
				parent string
				ev     evidence
			}{SessionKey(run, se.parent), evidence{Kind: "explicit_id", Weight: confExplicit, Refs: []EvidenceRef{se.ref}}}
		}
	}
	type span struct {
		key         string
		start, end  time.Time
		pid         int
		fingerprint string
	}
	var spans []span
	for key, ns := range bySession {
		spans = append(spans, span{key, ns[0].At, ns[len(ns)-1].At, ns[0].PID, ns[0].Fingerprint})
	}
	for _, s := range spans {
		if _, ok := parentOf[s.key]; ok {
			continue
		}
		for _, m := range spans {
			if m.key == s.key || m.pid != s.pid || m.fingerprint == s.fingerprint {
				continue
			}
			if !s.start.Before(m.start) && !s.start.After(m.end) && m.end.Sub(m.start) > s.end.Sub(s.start) {
				parentOf[s.key] = struct {
					parent string
					ev     evidence
				}{m.key, evidence{Kind: "nested_span", Weight: confFingerprint, Note: "child span nested in parent span, same pid, different fingerprint"}}
				break
			}
		}
	}
	// 6. write with new revision
	return d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var rev int64
		if err := tx.QueryRow(ctx, `update capture_runs set relation_revision = relation_revision + 1 where id=$1 returning relation_revision`, run).Scan(&rev); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update sessions set superseded=true where capture_run_id=$1 and relation_revision < $2`, run, rev); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update relations set superseded_by = -1 where capture_run_id=$1 and revision < $2 and superseded_by is null`, run, rev); err != nil {
			return err
		}
		aliasIDs := make([]string, 0, len(correlations))
		for alias, correlation := range correlations {
			if alias != correlation.Canonical {
				aliasIDs = append(aliasIDs, alias)
			}
		}
		if len(aliasIDs) > 0 {
			if _, err := tx.Exec(ctx, `delete from model_inferences where capture_run_id=$1 and id=any($2::text[])`, run, aliasIDs); err != nil {
				return err
			}
		}
		unattributed := 0
		for key, ns := range bySession {
			kind, native := "inferred", (*string)(nil)
			if nativeID, ok := nativeSessions[key]; ok {
				kind = "native"
				nid := nativeID
				native = &nid
			}
			role := "main"
			var parent *string
			if p, ok := parentOf[key]; ok {
				role = "subagent"
				pp := p.parent
				parent = &pp
			}
			tb, _ := json.Marshal(turnsBySession[key])
			var agentKind *string
			if _, err := tx.Exec(ctx, `insert into sessions(id, project_id, capture_run_id, kind, native_id, agent_kind, parent_session_id, role, turns, inference_count, first_seen_at, last_seen_at, relation_revision, superseded)
				values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,false)
				on conflict (id) do update set kind=excluded.kind, native_id=excluded.native_id, parent_session_id=excluded.parent_session_id, role=excluded.role, turns=excluded.turns, inference_count=excluded.inference_count, first_seen_at=excluded.first_seen_at, last_seen_at=excluded.last_seen_at, relation_revision=excluded.relation_revision, superseded=false`,
				key, j.ProjectID, run, kind, native, agentKind, parent, role, tb, len(ns), ns[0].At, ns[len(ns)-1].At, rev); err != nil {
				return err
			}
			if p, ok := parentOf[key]; ok {
				eb, _ := json.Marshal([]evidence{p.ev})
				st := "inferred"
				if p.ev.Weight >= confExplicit {
					st = "observed"
				}
				if _, err := tx.Exec(ctx, `insert into relations(project_id, capture_run_id, type, from_id, to_id, status, confidence, evidence, revision) values($1,$2,'parent_of',$3,$4,$5,$6,$7,$8)`, j.ProjectID, run, p.parent, key, st, p.ev.Weight, eb, rev); err != nil {
					return err
				}
			}
		}
		for _, n := range list {
			turnID := ""
			for _, t := range turnsBySession[n.sessionKey] {
				if t["index"].(int) == n.turnIndex {
					turnID, _ = t["turn_id"].(string)
				}
			}
			status := "inferred"
			if n.Observed {
				status = "observed"
			}
			var normB any
			if n.Norm != nil {
				normB, _ = json.Marshal(n.Norm)
			}
			evB, _ := json.Marshal(n.Evidence)
			fp, _ := hex.DecodeString(n.Fingerprint)
			ih, _ := hex.DecodeString(n.InputHash)
			serverState := "none"
			if n.Norm != nil && len(n.Norm.ServerStateRefs) > 0 {
				serverState = "unresolved"
				if n.prev != nil && n.prevEv.Kind == "response_id_chain" {
					serverState = "resolved"
				}
			}
			taskKey := resolvedTaskKey(run, n.TaskID, n.SessionID)
			if _, err := tx.Exec(ctx, `insert into model_inferences(id, recording_id, capture_run_id, project_id, status, attempt_count, first_attempt_at, model, api_mode, request_fingerprint, input_hash, request, response, usage, normalized, server_state, task_id, session_id, turn_id, pid, evidence_refs, processor_version, relation_revision)
				values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
				on conflict (id) do update set status=excluded.status, attempt_count=excluded.attempt_count, first_attempt_at=excluded.first_attempt_at, model=coalesce(excluded.model,model_inferences.model), api_mode=coalesce(nullif(excluded.api_mode,'unknown'),model_inferences.api_mode),
					request_fingerprint=coalesce(excluded.request_fingerprint,model_inferences.request_fingerprint), input_hash=coalesce(excluded.input_hash,model_inferences.input_hash), request=coalesce(excluded.request,model_inferences.request), response=coalesce(excluded.response,model_inferences.response), usage=coalesce(excluded.usage,model_inferences.usage), normalized=coalesce(excluded.normalized,model_inferences.normalized),
					server_state=excluded.server_state, task_id=excluded.task_id, session_id=excluded.session_id, turn_id=excluded.turn_id, pid=coalesce(excluded.pid,model_inferences.pid), evidence_refs=excluded.evidence_refs, relation_revision=excluded.relation_revision, updated_at=now()`,
				n.ID, n.Recording, run, j.ProjectID, status, len(n.Attempts), n.At, nilIfEmpty(n.Model), orUnknown(n.APIMode), fp, ih, nullJSON(n.Request), nullJSON(n.Response), nullJSON(n.Usage), normB, serverState, taskKey, n.sessionKey, nilIfEmpty(turnID), nilIfZero(n.PID), evB, ResolverVersion, rev); err != nil {
				return err
			}
			for _, a := range n.Attempts {
				st, conf, kind := "observed", confExplicit, "explicit_id"
				relationEvidence := evidence{Kind: kind, Weight: conf, Refs: []EvidenceRef{{RecordingID: a.Recording, FirstSeq: a.FirstSeq, LastSeq: a.Last}}}
				if a.InferenceID == "" {
					st, conf, kind = "inferred", confInputHash, "input_hash_retry_group"
					if len(n.Attempts) == 1 && !n.Observed {
						conf, kind = confExplicit, "single_attempt"
					}
					relationEvidence = evidence{Kind: kind, Weight: conf, Refs: []EvidenceRef{{RecordingID: a.Recording, FirstSeq: a.FirstSeq, LastSeq: a.Last}}}
				} else if a.Correlation != nil {
					st, conf, kind = "inferred", a.Correlation.Weight, a.Correlation.Kind
					if conf >= confExplicit {
						st = "observed"
					}
					relationEvidence = *a.Correlation
					relationEvidence.Refs = append(append([]EvidenceRef(nil), relationEvidence.Refs...), EvidenceRef{RecordingID: a.Recording, FirstSeq: a.FirstSeq, LastSeq: a.Last})
				}
				eb, _ := json.Marshal([]evidence{relationEvidence})
				if _, err := tx.Exec(ctx, `insert into relations(project_id, capture_run_id, type, from_id, to_id, status, confidence, evidence, revision) values($1,$2,'attempt_of',$3,$4,$5,$6,$7,$8)`, j.ProjectID, run, a.ID, n.ID, st, conf, eb, rev); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `update model_attempts set inference_id=$2 where id=$1`, a.ID, n.ID); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `update model_attempts set task_id=coalesce($2,task_id), session_id=coalesce($3,session_id) where id=$1`, a.ID, taskKey, n.sessionKey); err != nil {
					return err
				}
			}
			// belongs_to_turn
			st := "inferred"
			conf := confPrefixChain
			kind := "session_chain"
			if n.SessionID != "" {
				st, conf, kind = "observed", confExplicit, "explicit_id"
			} else if n.prev != nil {
				conf, kind = n.prevEv.Weight, n.prevEv.Kind
			} else if len(bySession[n.sessionKey]) == 1 {
				conf, kind = confExplicit, "singleton_session"
			}
			if n.conflict {
				st = "conflict"
			}
			eb, _ := json.Marshal([]evidence{{Kind: kind, Weight: conf, Refs: n.Evidence}})
			if _, err := tx.Exec(ctx, `insert into relations(project_id, capture_run_id, type, from_id, to_id, status, confidence, evidence, revision) values($1,$2,'belongs_to_turn',$3,$4,$5,$6,$7,$8)`, j.ProjectID, run, n.ID, n.sessionKey+"/"+turnID, st, conf, eb, rev); err != nil {
				return err
			}
			if n.prev != nil {
				eb, _ := json.Marshal([]evidence{n.prevEv})
				if _, err := tx.Exec(ctx, `insert into relations(project_id, capture_run_id, type, from_id, to_id, status, confidence, evidence, revision) values($1,$2,'follows',$3,$4,$5,$6,$7,$8)`, j.ProjectID, run, n.ID, n.prev.ID, "inferred", n.prevEv.Weight, eb, rev); err != nil {
					return err
				}
			}
			if n.Norm == nil || n.Norm.BodyUnavailable {
				unattributed += len(n.Attempts)
			}
		}
		if _, err := tx.Exec(ctx, `delete from relations where capture_run_id=$1 and superseded_by = -1 and revision < $2 - 5`, run, rev); err != nil {
			return err
		}
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: j.ProjectID, Type: jobs.TypeTransportAudit, CaptureRunID: run, InputRef: map[string]any{"relation_revision": rev}, ProcessorVersion: TransportAuditVersion, Priority: 5}); err != nil {
			return err
		}
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: j.ProjectID, Type: jobs.TypeRules, CaptureRunID: run, InputRef: map[string]any{"relation_revision": rev}, ProcessorVersion: RulesVersion, Priority: 2}); err != nil {
			return err
		}
		return d.publishTx(ctx, tx, j.ProjectID, "capture_run", run, "relation_revision", rev)
	})
}

func normalizedProjectionScore(n *Normalized, terminal string) int {
	if n == nil {
		return -1
	}
	score := 0
	if !n.BodyUnavailable {
		score += 100
	}
	if strings.TrimSpace(n.ResponseText) != "" || len(n.ResponseToolCalls) > 0 {
		score += 20
	}
	switch terminal {
	case "completed":
		score += 30
	case "error":
		score += 10
	case "cancelled", "truncated":
		score += 5
	}
	return score
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func absDur(a, b time.Time) time.Duration {
	if a.After(b) {
		return a.Sub(b)
	}
	return b.Sub(a)
}

// linkEvidence returns the strongest evidence that cur continues prev.
func linkEvidence(prev, cur *inferenceNode) (evidence, bool) {
	p, c := prev.Norm, cur.Norm
	if c.PreviousResponseID != "" && p.ResponseID != "" && c.PreviousResponseID == p.ResponseID {
		return evidence{Kind: "response_id_chain", Weight: confResponseID}, true
	}
	if len(c.MessageHashes) > len(p.MessageHashes) && len(p.MessageHashes) > 0 && isPrefix(p.MessageHashes, c.MessageHashes) {
		return evidence{Kind: "prefix_chain", Weight: confPrefixChain}, true
	}
	for _, m := range c.Messages {
		if m.ToolCallID == "" {
			continue
		}
		for _, tc := range p.ResponseToolCalls {
			if tc.ID != "" && tc.ID == m.ToolCallID {
				return evidence{Kind: "tool_call_id_match", Weight: confToolCallID}, true
			}
		}
	}
	if prev.PID == cur.PID && prev.Fingerprint != "" && prev.Fingerprint == cur.Fingerprint && absDur(prev.At, cur.At) < adjacencyWindow {
		// compaction: same fingerprint, prefix broke
		return evidence{Kind: "fingerprint", Weight: confFingerprint, Note: "same system prompt/tools, prefix chain broken (possible compaction)"}, true
	}
	if prev.PID == cur.PID && prev.PID != 0 && absDur(prev.At, cur.At) < adjacencyWindow {
		return evidence{Kind: "temporal_pid", Weight: confTemporalPID}, true
	}
	return evidence{}, false
}

func isPrefix(a, b []string) bool {
	if len(a) > len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func resolvedTaskKey(run, taskID, sessionID string) *string {
	if taskID != "" {
		taskPrefix := fmt.Sprintf("task:agent_task:%d:%s:", len(run), run)
		sessionPrefix := fmt.Sprintf("task:agent_session:%d:%s:", len(run), run)
		if strings.HasPrefix(taskID, taskPrefix) || strings.HasPrefix(taskID, sessionPrefix) {
			return &taskID
		}
		key := TaskKey(run, "agent_task", taskID)
		return &key
	}
	if sessionID == "" {
		return nil
	}
	key := TaskKey(run, "agent_session", sessionID)
	return &key
}

func (d *Deps) loadAttempts(ctx context.Context, run string) ([]*attemptRow, error) {
	rows, err := d.DB.Pool.Query(ctx, `select a.id, a.recording_id,
		coalesce((select e.inference_id from recording_events e join recordings er on er.id=e.recording_id
			where er.capture_run_id=a.capture_run_id and e.attempt_id=a.native_id and e.inference_id is not null order by e.seq limit 1),''),
		a.source, coalesce(a.pid,0), coalesce(a.started_at, now()), coalesce(encode(a.input_hash,'hex'),''), coalesce(encode(a.request_fingerprint,'hex'),''), coalesce(a.provider_host,''), a.terminal_state, coalesce(a.first_seq,0), coalesce(a.last_seq,0), a.normalized
		from model_attempts a where a.capture_run_id=$1 order by a.started_at`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*attemptRow
	for rows.Next() {
		a := &attemptRow{}
		var norm json.RawMessage
		var nativeInferenceID string
		if err := rows.Scan(&a.ID, &a.Recording, &nativeInferenceID, &a.Source, &a.PID, &a.StartedAt, &a.InputHash, &a.Fingerprint, &a.Host, &a.Terminal, &a.FirstSeq, &a.Last, &norm); err != nil {
			return nil, err
		}
		if nativeInferenceID != "" {
			a.InferenceID = InferenceKey(run, nativeInferenceID)
		}
		if len(norm) > 0 {
			var n Normalized
			if json.Unmarshal(norm, &n) == nil {
				a.Norm = &n
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *Deps) loadObservedInferences(ctx context.Context, run string) ([]*inferenceNode, error) {
	rows, err := d.DB.Pool.Query(ctx, `select i.id, i.recording_id, coalesce(i.pid,0), coalesce(i.first_attempt_at, now()), coalesce(encode(i.input_hash,'hex'),''), coalesce(encode(i.request_fingerprint,'hex'),''),
		coalesce((select e.task_id from recording_events e join recordings er on er.id=e.recording_id where er.capture_run_id=i.capture_run_id and e.inference_id=i.native_id and e.task_id is not null order by e.seq limit 1),case when coalesce(i.task_id,'') not like 'task:%' then i.task_id end,''),
		coalesce((select e.agent_session_id from recording_events e join recordings er on er.id=e.recording_id where er.capture_run_id=i.capture_run_id and e.inference_id=i.native_id and e.agent_session_id is not null order by e.seq limit 1),case when coalesce(i.session_id,'') not like 'sess:%' then i.session_id end,''),
		coalesce((select e.turn_id from recording_events e join recordings er on er.id=e.recording_id where er.capture_run_id=i.capture_run_id and e.inference_id=i.native_id and e.turn_id is not null order by e.seq limit 1),case when coalesce(i.turn_id,'') not like 'sess:%' then i.turn_id end,''),
		coalesce(i.task_id,''),coalesce(i.session_id,''),coalesce((select s.native_id from sessions s where s.id=i.session_id and s.capture_run_id=i.capture_run_id and s.kind='native' order by s.superseded,s.relation_revision desc limit 1),''),
		i.normalized, i.request, i.response, i.usage, i.evidence_refs, coalesce(i.model,''), coalesce(i.api_mode,'')
		from model_inferences i where i.capture_run_id=$1 and i.status='observed'`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*inferenceNode
	for rows.Next() {
		n := &inferenceNode{Observed: true}
		var norm, ev json.RawMessage
		var storedTask, storedSession, recoveredSession string
		if err := rows.Scan(&n.ID, &n.Recording, &n.PID, &n.At, &n.InputHash, &n.Fingerprint, &n.TaskID, &n.SessionID, &n.TurnID, &storedTask, &storedSession, &recoveredSession, &norm, &n.Request, &n.Response, &n.Usage, &ev, &n.Model, &n.APIMode); err != nil {
			return nil, err
		}
		if n.TaskID == "" {
			n.TaskID = nativeTaskID(run, storedTask)
		}
		if n.SessionID == "" && storedSession != "sess:"+n.ID {
			n.SessionID = recoveredSession
		}
		if len(norm) > 0 {
			var nn Normalized
			if json.Unmarshal(norm, &nn) == nil {
				n.Norm = &nn
			}
		}
		_ = json.Unmarshal(ev, &n.Evidence)
		out = append(out, n)
	}
	return out, rows.Err()
}

func nativeTaskID(run, stored string) string {
	prefix := fmt.Sprintf("task:agent_task:%d:%s:", len(run), run)
	if strings.HasPrefix(stored, prefix) {
		return strings.TrimPrefix(stored, prefix)
	}
	return ""
}

type inferenceCorrelation struct {
	Canonical         string
	Recording         string
	At                time.Time
	TaskID, SessionID string
	TurnID            string
	Evidence          evidence
}

func (d *Deps) loadInferenceCorrelations(ctx context.Context, run string) (map[string]inferenceCorrelation, map[string]inferenceCorrelation, error) {
	rows, err := d.DB.Pool.Query(ctx, `select e.recording_id,e.seq,e.wall_time,coalesce(e.inference_id,''),coalesce(e.task_id,''),coalesce(e.agent_session_id,''),coalesce(e.turn_id,''),e.payload,coalesce(e.confidence,0)
		from recording_events e join recordings r on r.id=e.recording_id
		where r.capture_run_id=$1 and e.event='inference_correlation' order by e.seq,e.recording_id`, run)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	aliases := map[string]inferenceCorrelation{}
	sessions := map[string]inferenceCorrelation{}
	for rows.Next() {
		var recording, transportNative, taskID, sessionID, turnID string
		var seq int64
		var at time.Time
		var payload json.RawMessage
		var confidence float64
		if err := rows.Scan(&recording, &seq, &at, &transportNative, &taskID, &sessionID, &turnID, &payload, &confidence); err != nil {
			return nil, nil, err
		}
		var body struct {
			NativeInferenceID string `json:"native_inference_id"`
			Method            string `json:"method"`
		}
		if json.Unmarshal(payload, &body) != nil || transportNative == "" || body.Method == "" {
			return nil, nil, fmt.Errorf("malformed inference_correlation event at %s:%d", recording, seq)
		}
		if confidence <= 0 || confidence > 1 {
			return nil, nil, fmt.Errorf("invalid inference_correlation confidence at %s:%d", recording, seq)
		}
		correlation := inferenceCorrelation{
			Canonical: InferenceKey(run, transportNative), Recording: recording, At: at,
			TaskID: taskID, SessionID: sessionID, TurnID: turnID,
			Evidence: evidence{
				Kind:   "cross_source_" + orUnknown(body.Method),
				Weight: confidence,
				Refs:   []EvidenceRef{{RecordingID: recording, FirstSeq: seq, LastSeq: seq}},
			},
		}
		if body.NativeInferenceID != "" {
			alias := InferenceKey(run, body.NativeInferenceID)
			if existing, ok := aliases[alias]; ok && existing.Canonical != correlation.Canonical {
				return nil, nil, fmt.Errorf("conflicting inference_correlation targets for %s", alias)
			}
			aliases[alias] = correlation
		}
		if taskID != "" || sessionID != "" || turnID != "" {
			if existing, ok := sessions[correlation.Canonical]; ok &&
				((existing.TaskID != "" && taskID != "" && existing.TaskID != taskID) ||
					(existing.SessionID != "" && sessionID != "" && existing.SessionID != sessionID) ||
					(existing.TurnID != "" && turnID != "" && existing.TurnID != turnID)) {
				return nil, nil, fmt.Errorf("conflicting inference session correlations for %s", correlation.Canonical)
			}
			sessions[correlation.Canonical] = correlation
		}
		if body.NativeInferenceID == "" && taskID == "" && sessionID == "" && turnID == "" {
			return nil, nil, fmt.Errorf("inference_correlation event has no alias or identity at %s:%d", recording, seq)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return aliases, sessions, nil
}

func mergeInferenceNode(target, source *inferenceNode) {
	target.Observed = target.Observed || source.Observed
	if target.Recording == "" {
		target.Recording = source.Recording
	}
	if target.At.IsZero() || (!source.At.IsZero() && source.At.Before(target.At)) {
		target.At = source.At
	}
	if target.PID == 0 {
		target.PID = source.PID
	}
	if target.InputHash == "" {
		target.InputHash = source.InputHash
	}
	if target.Fingerprint == "" {
		target.Fingerprint = source.Fingerprint
	}
	if target.TaskID == "" {
		target.TaskID = source.TaskID
	}
	if target.SessionID == "" {
		target.SessionID = source.SessionID
	}
	if target.TurnID == "" {
		target.TurnID = source.TurnID
	}
	if target.Norm == nil || (target.Norm.BodyUnavailable && source.Norm != nil && !source.Norm.BodyUnavailable) {
		target.Norm = source.Norm
	}
	if len(target.Request) == 0 {
		target.Request = source.Request
	}
	if len(target.Response) == 0 {
		target.Response = source.Response
	}
	if len(target.Usage) == 0 {
		target.Usage = source.Usage
	}
	target.Evidence = append(target.Evidence, source.Evidence...)
}

type subagentEvent struct {
	child, parent string
	ref           EvidenceRef
}

func (d *Deps) loadSubagentEvents(ctx context.Context, run string) ([]subagentEvent, error) {
	rows, err := d.DB.Pool.Query(ctx, `select e.recording_id, e.seq, e.payload, coalesce(e.agent_session_id,''), coalesce(e.parent_span_id,'') from recording_events e join recordings r on r.id=e.recording_id where r.capture_run_id=$1 and e.event='subagent_start'`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []subagentEvent
	for rows.Next() {
		var rec, sess, parentSpan string
		var seq int64
		var payload json.RawMessage
		if err := rows.Scan(&rec, &seq, &payload, &sess, &parentSpan); err != nil {
			return nil, err
		}
		var p struct {
			ChildSessionID  string `json:"child_session_id"`
			ParentSessionID string `json:"parent_session_id"`
		}
		_ = json.Unmarshal(payload, &p)
		child, parent := p.ChildSessionID, p.ParentSessionID
		if child == "" {
			child = sess
		}
		if parent == "" {
			parent = parentSpan
		}
		out = append(out, subagentEvent{child: child, parent: parent, ref: EvidenceRef{RecordingID: rec, FirstSeq: seq, LastSeq: seq}})
	}
	return out, rows.Err()
}
