package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/jobs"
)

// Finding is produced by a rule.
type Finding struct {
	RuleID      string
	Severity    string
	Title       string
	Detail      map[string]any
	Evidence    []EvidenceRef
	EvidenceKey string
	RecordingID string
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-_.=]{24,}`),
}

func knownModelAPIMode(apiMode string) bool {
	switch apiMode {
	case "chat_completions", "completions", "anthropic_messages", "responses", "codex_responses", "gemini_generate":
		return true
	default:
		return false
	}
}

func responseProjectionMissing(apiMode string, status *int, terminal string, responseText *string, toolCallCount int) bool {
	return knownModelAPIMode(apiMode) && status != nil && *status >= 200 && *status < 300 && terminal == "completed" &&
		(responseText == nil || strings.TrimSpace(*responseText) == "") && toolCallCount == 0
}

// Rules evaluates deterministic rules for a capture run (platform/07 §2).
func (d *Deps) Rules(ctx context.Context, j *jobs.Job) error {
	run := runIDOf(j)
	return d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, "iorec-analysis:"+run); err != nil {
			return err
		}
		pool := tx
		var findings []Finding
		// retry_storm & provider_switch & unattributed
		rows, err := pool.Query(ctx, `select i.id, i.recording_id, i.attempt_count, i.evidence_refs, coalesce(array_agg(distinct a.provider_host) filter (where a.provider_host is not null), '{}')
		from model_inferences i left join model_attempts a on a.inference_id=i.id where i.capture_run_id=$1 group by i.id`, run)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, rec string
			var attempts int
			var ev json.RawMessage
			var hosts []string
			if err := rows.Scan(&id, &rec, &attempts, &ev, &hosts); err != nil {
				rows.Close()
				return err
			}
			var refs []EvidenceRef
			_ = json.Unmarshal(ev, &refs)
			if attempts >= 4 {
				findings = append(findings, Finding{RuleID: "retry_storm", Severity: "warn", Title: fmt.Sprintf("同一逻辑调用 %d 次物理重试", attempts), Detail: map[string]any{"inference_id": id, "attempts": attempts, "hosts": hosts}, Evidence: refs, EvidenceKey: id, RecordingID: rec})
			}
			if len(hosts) > 1 {
				findings = append(findings, Finding{RuleID: "provider_switch", Severity: "info", Title: "同一逻辑调用跨多个 provider host（fallback 生效）", Detail: map[string]any{"inference_id": id, "hosts": hosts}, Evidence: refs, EvidenceKey: id, RecordingID: rec})
			}
		}
		rows.Close()
		// attempt-level
		rows, err = pool.Query(ctx, `select id, recording_id, source, terminal_state, coalesce(first_seq,0), coalesce(last_seq,0), normalized->>'response_text', normalized->'messages', started_at, ended_at, model,
		status_code, coalesce(api_mode,'unknown'), case when jsonb_typeof(normalized->'response_tool_calls')='array' then jsonb_array_length(normalized->'response_tool_calls') else 0 end,
		coalesce((normalized->>'body_unavailable')::boolean,false),
		exists(select 1 from model_attempts companion where companion.inference_id=model_attempts.inference_id and companion.id<>model_attempts.id and not coalesce((companion.normalized->>'body_unavailable')::boolean,false))
		from model_attempts where capture_run_id=$1`, run)
		if err != nil {
			return err
		}
		type attemptLite struct {
			id, rec, source, terminal, model string
			first, last                      int64
		}
		var truncated []attemptLite
		var noTerminal []attemptLite
		var secretHits []Finding
		var projectionGaps []Finding
		for rows.Next() {
			var a attemptLite
			var respText *string
			var msgs json.RawMessage
			var started, ended *time.Time
			var model *string
			var status *int
			var apiMode string
			var toolCallCount int
			var bodyUnavailable bool
			var companionBodyAvailable bool
			if err := rows.Scan(&a.id, &a.rec, &a.source, &a.terminal, &a.first, &a.last, &respText, &msgs, &started, &ended, &model, &status, &apiMode, &toolCallCount, &bodyUnavailable, &companionBodyAvailable); err != nil {
				rows.Close()
				return err
			}
			if model != nil {
				a.model = *model
			}
			_, _ = started, ended
			switch a.terminal {
			case "truncated":
				truncated = append(truncated, a)
			case "unknown":
				noTerminal = append(noTerminal, a)
			}
			if knownModelAPIMode(apiMode) && bodyUnavailable && !(strings.HasPrefix(a.source, "hook:") && companionBodyAvailable) {
				projectionGaps = append(projectionGaps, Finding{RuleID: "model_body_unavailable", Severity: "warn", Title: "模型调用正文无法重组", Detail: map[string]any{"attempt_id": a.id, "api_mode": apiMode}, Evidence: []EvidenceRef{{a.rec, a.first, a.last}}, EvidenceKey: a.id, RecordingID: a.rec})
			}
			if responseProjectionMissing(apiMode, status, a.terminal, respText, toolCallCount) {
				projectionGaps = append(projectionGaps, Finding{RuleID: "model_response_projection_missing", Severity: "warn", Title: "成功的模型响应没有可展示文本或工具调用", Detail: map[string]any{"attempt_id": a.id, "api_mode": apiMode, "status_code": status}, Evidence: []EvidenceRef{{a.rec, a.first, a.last}}, EvidenceKey: a.id, RecordingID: a.rec})
			}
			if len(msgs) > 0 {
				var ms []NMessage
				_ = json.Unmarshal(msgs, &ms)
				for idx, m := range ms {
					for _, re := range secretPatterns {
						if re.MatchString(m.Text) {
							secretHits = append(secretHits, Finding{RuleID: "secret_in_prompt", Severity: "high", Title: "模型输入正文中出现疑似凭证", Detail: map[string]any{"attempt_id": a.id, "message_index": idx, "pattern": re.String()}, Evidence: []EvidenceRef{{a.rec, a.first, a.last}}, EvidenceKey: fmt.Sprintf("%s#%d#%s", a.id, idx, re.String()), RecordingID: a.rec})
							break
						}
					}
				}
			}
		}
		rows.Close()
		findings = append(findings, projectionGaps...)
		for _, a := range truncated {
			findings = append(findings, Finding{RuleID: "stream_truncated", Severity: "warn", Title: "流式响应在终止标记前结束", Detail: map[string]any{"attempt_id": a.id}, Evidence: []EvidenceRef{{a.rec, a.first, a.last}}, EvidenceKey: a.id, RecordingID: a.rec})
		}
		var sealedRecs = map[string]bool{}
		srows, err := pool.Query(ctx, `select id from recordings where capture_run_id=$1 and state <> 'open'`, run)
		if err != nil {
			return err
		}
		for srows.Next() {
			var id string
			_ = srows.Scan(&id)
			sealedRecs[id] = true
		}
		srows.Close()
		for _, a := range noTerminal {
			if sealedRecs[a.rec] {
				findings = append(findings, Finding{RuleID: "attempt_without_terminal", Severity: "warn", Title: "录制已封存但 attempt 没有终态", Detail: map[string]any{"attempt_id": a.id}, Evidence: []EvidenceRef{{a.rec, a.first, a.last}}, EvidenceKey: a.id, RecordingID: a.rec})
			}
		}
		findings = append(findings, secretHits...)
		// unattributed ratio & duplicate_request per recording, coverage mismatch
		rrows, err := pool.Query(ctx, `select id, coverage from recordings where capture_run_id=$1`, run)
		if err != nil {
			return err
		}
		type recCov struct {
			id  string
			cov Coverage
		}
		var recs []recCov
		for rrows.Next() {
			var rc recCov
			var cb json.RawMessage
			if err := rrows.Scan(&rc.id, &cb); err != nil {
				rrows.Close()
				return err
			}
			_ = json.Unmarshal(cb, &rc.cov)
			recs = append(recs, rc)
		}
		rrows.Close()
		for _, rc := range recs {
			if rc.cov.TransportAttempts > 0 && float64(rc.cov.BodyUnavailable)/float64(rc.cov.TransportAttempts) > 0.10 {
				findings = append(findings, Finding{RuleID: "unattributed_ratio", Severity: "warn", Title: "超过 10% 的 attempt 正文不可用", Detail: map[string]any{"body_unavailable": rc.cov.BodyUnavailable, "attempts": rc.cov.TransportAttempts}, Evidence: []EvidenceRef{{rc.id, 1, 1}}, EvidenceKey: rc.id + "#" + fmt.Sprint(rc.cov.RelationRevision), RecordingID: rc.id})
			}
			if rc.cov.CollectorClaim != "" && claimRank[rc.cov.CollectorClaim] > claimRank[rc.cov.Claim] {
				findings = append(findings, Finding{RuleID: "coverage_claim_mismatch", Severity: "warn", Title: "采集端声明的 coverage 高于平台重算结果", Detail: map[string]any{"collector_claim": rc.cov.CollectorClaim, "platform_claim": rc.cov.Claim}, Evidence: []EvidenceRef{{rc.id, 1, 1}}, EvidenceKey: rc.id, RecordingID: rc.id})
			}
			if rc.cov.UnknownEgress > 0 {
				findings = append(findings, Finding{RuleID: "unknown_egress", Severity: "warn", Title: "存在未分类且未记录的外联", Detail: map[string]any{"count": rc.cov.UnknownEgress}, Evidence: []EvidenceRef{{rc.id, 1, 1}}, EvidenceKey: rc.id, RecordingID: rc.id})
			}
		}
		// duplicate_request: same input_hash across different inferences (non-retry) in run
		drows, err := pool.Query(ctx, `select encode(input_hash,'hex'), array_agg(id), min(recording_id) from model_inferences where capture_run_id=$1 and input_hash is not null group by input_hash having count(*) > 1`, run)
		if err != nil {
			return err
		}
		for drows.Next() {
			var h, rec string
			var ids []string
			if err := drows.Scan(&h, &ids, &rec); err != nil {
				drows.Close()
				return err
			}
			findings = append(findings, Finding{RuleID: "duplicate_request", Severity: "info", Title: "相同输入被作为不同逻辑调用发送多次", Detail: map[string]any{"input_hash": h, "inference_ids": ids}, Evidence: []EvidenceRef{{rec, 1, 1}}, EvidenceKey: h, RecordingID: rec})
		}
		drows.Close()
		// tool_loop: same tool + args repeated >=3 consecutively within a session
		trows, err := pool.Query(ctx, `select session_id, id, normalized->'response_tool_calls', recording_id from model_inferences where capture_run_id=$1 and session_id is not null order by session_id, first_attempt_at`, run)
		if err != nil {
			return err
		}
		lastKey, lastSess := "", ""
		streak := 0
		for trows.Next() {
			var sess, id, rec string
			var tcs json.RawMessage
			if err := trows.Scan(&sess, &id, &tcs, &rec); err != nil {
				trows.Close()
				return err
			}
			var calls []NToolCall
			_ = json.Unmarshal(tcs, &calls)
			key := ""
			for _, c := range calls {
				key += c.Name + ":" + c.ArgsHash + ";"
			}
			if sess == lastSess && key != "" && key == lastKey {
				streak++
				if streak == 3 {
					findings = append(findings, Finding{RuleID: "tool_loop", Severity: "warn", Title: "同一工具以相同参数连续调用 ≥ 3 次", Detail: map[string]any{"session_id": sess, "inference_id": id, "calls": strings.TrimSuffix(key, ";")}, Evidence: []EvidenceRef{{rec, 1, 1}}, EvidenceKey: sess + "#" + id, RecordingID: rec})
				}
			} else {
				streak = 1
			}
			lastKey, lastSess = key, sess
		}
		trows.Close()
		// write
		var rev int64
		if err := tx.QueryRow(ctx, `update capture_runs set analysis_revision = analysis_revision + 1 where id=$1 returning analysis_revision`, run).Scan(&rev); err != nil {
			return err
		}
		// Open findings are a materialized view of the current analysis pass.
		// Remove stale, unreviewed rows atomically; confirmed/dismissed decisions
		// remain durable audit records and keep their conflict behavior below.
		if _, err := tx.Exec(ctx, `delete from findings where project_id=$1 and capture_run_id=$2 and status='open'`, j.ProjectID, run); err != nil {
			return err
		}
		for _, f := range findings {
			det, _ := json.Marshal(f.Detail)
			ev, _ := json.Marshal(f.Evidence)
			if _, err := tx.Exec(ctx, `insert into findings(id, project_id, capture_run_id, recording_id, rule_id, severity, title, detail, evidence_refs, evidence_key, status, analysis_revision, processor_version)
				values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11,$12)
				on conflict (project_id, rule_id, evidence_key) do update set detail=excluded.detail, evidence_refs=excluded.evidence_refs, analysis_revision=excluded.analysis_revision, title=excluded.title
				where findings.status <> 'dismissed'`,
				uuid.New(), j.ProjectID, run, f.RecordingID, f.RuleID, f.Severity, f.Title, det, ev, f.EvidenceKey, rev, RulesVersion); err != nil {
				return err
			}
		}
		return d.publishTx(ctx, tx, j.ProjectID, "capture_run", run, "analysis_revision", rev)
	})
}
