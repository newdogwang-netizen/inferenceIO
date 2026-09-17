package pipeline

import (
	"context"
	"encoding/json"

	"github.com/heidihealth/iorec-platform/internal/jobs"
)

// Coverage is the platform-recomputed manifest (platform/07 §5).
type Coverage struct {
	Claim                        string         `json:"claim"`
	CollectorClaim               string         `json:"collector_claim,omitempty"`
	CaptureSources               []string       `json:"capture_sources"`
	TLSSurfaces                  []any          `json:"tls_surfaces"`
	UnknownTLSSurfaces           int            `json:"unknown_tls_surfaces"`
	LogicalInferences            int            `json:"logical_inferences"`
	TransportAttempts            int            `json:"transport_attempts"`
	UnattributedAttempts         int            `json:"unattributed_attempts"`
	UnparsedConnections          int            `json:"unparsed_connections"`
	CaptureDrops                 int64          `json:"capture_drops"`
	GapEvents                    int            `json:"gap_events"`
	UnknownEgress                int            `json:"unknown_egress"`
	ModelBypassConnections       int            `json:"model_bypass_connections"`
	ObservedEgressClasses        map[string]int `json:"observed_egress_classes"`
	AllAttemptsHaveTerminalState bool           `json:"all_attempts_have_terminal_state"`
	UnresolvedServerState        int            `json:"unresolved_server_state"`
	MissingBlobs                 int            `json:"missing_blobs"`
	BodyUnavailable              int            `json:"body_unavailable"`
	CapabilitiesKnown            bool           `json:"capabilities_known"`
	// PlatformTransportProofVerified is set only by a platform-owned decoder
	// after it has independently validated a bounded task-egress capture and
	// payload agreement. Collector manifests and ordinary events never set it.
	PlatformTransportProofVerified bool     `json:"platform_transport_proof_verified"`
	PlatformTransportProofStatus   string   `json:"platform_transport_proof_status"`
	PlatformTransportProofVersion  string   `json:"platform_transport_proof_version,omitempty"`
	Incomplete                     bool     `json:"incomplete"`
	KnownGaps                      []string `json:"known_gaps"`
	RelationRevision               int64    `json:"relation_revision"`
	ProcessorVersion               string   `json:"processor_version"`
}

var claimRank = map[string]int{"unknown": 0, "best-effort": 1, "transport-complete": 2, "client-complete": 3, "server-effective-complete": 4}

// Coverage recomputes recordings.coverage.
func (d *Deps) Coverage(ctx context.Context, j *jobs.Job) error {
	rec := *j.RecordingID
	c := Coverage{Claim: "best-effort", CaptureSources: []string{}, TLSSurfaces: []any{}, ObservedEgressClasses: map[string]int{}, KnownGaps: []string{}, ProcessorVersion: CoverageVersion}
	pool := d.DB.Pool
	// sources
	srcs, err := scanStrings(pool.Query(ctx, `select distinct source from recording_events where recording_id=$1`, rec))
	if err != nil {
		return err
	}
	c.CaptureSources = srcs
	// capability report / tls surfaces / drops / unknown egress / gaps / manifest
	rows, err := pool.Query(ctx, `select event, payload from recording_events where recording_id=$1 and event in ('capability_report','tls_surface','drop_counter','unknown_egress','gap','manifest')`, rec)
	if err != nil {
		return err
	}
	var manifest map[string]any
	var collectorUnknownTLS, collectorUnparsed, collectorUnknownEgress, collectorModelBypass int
	var collectorDrops int64
	for rows.Next() {
		var ev string
		var payload json.RawMessage
		if err := rows.Scan(&ev, &payload); err != nil {
			rows.Close()
			return err
		}
		var p map[string]any
		_ = json.Unmarshal(payload, &p)
		switch ev {
		case "capability_report":
			c.CapabilitiesKnown = true
			if ri, ok := p["runtime_inventory"].(map[string]any); ok {
				if u, ok := ri["unknown_tls_surfaces"].(float64); ok {
					c.UnknownTLSSurfaces += int(u)
				}
			}
		case "tls_surface":
			c.TLSSurfaces = append(c.TLSSurfaces, p)
			if st, _ := p["status"].(string); st == "unknown" {
				c.UnknownTLSSurfaces++
			}
		case "drop_counter":
			if n, ok := p["count"].(float64); ok {
				c.CaptureDrops += int64(n)
			}
		case "unknown_egress":
			c.UnknownEgress++
		case "gap":
			c.GapEvents++
			if n, ok := p["estimated_events"].(float64); ok {
				c.CaptureDrops += int64(n)
			} else {
				c.CaptureDrops++
			}
		case "manifest":
			manifest = p
		}
	}
	rows.Close()
	// Recompute classes from immutable connection evidence. Unknown class
	// labels fail closed; missing connection IDs are counted by sequence.
	egressRows, err := pool.Query(ctx, `select
		case when payload->>'traffic_class' in ('model_recorder','model_bypass','local','auth','telemetry','update','other','unknown_external')
			then payload->>'traffic_class' else 'unknown_external' end as traffic_class,
		count(distinct coalesce(connection_id, 'sequence:' || seq::text))
		from recording_events
		where recording_id=$1 and source='process' and event='network_connection_observed'
		group by 1`, rec)
	if err != nil {
		return err
	}
	for egressRows.Next() {
		var class string
		var count int64
		if err := egressRows.Scan(&class, &count); err != nil {
			egressRows.Close()
			return err
		}
		mergeEgressCount(&c, class, jsonInt(count))
	}
	if err := egressRows.Err(); err != nil {
		egressRows.Close()
		return err
	}
	egressRows.Close()
	if manifest == nil {
		var m json.RawMessage
		_ = pool.QueryRow(ctx, `select manifest from recordings where id=$1`, rec).Scan(&m)
		if len(m) > 0 {
			_ = json.Unmarshal(m, &manifest)
		}
	}
	if manifest != nil {
		collectorCoverage := manifest
		if nested, ok := manifest["coverage"].(map[string]any); ok {
			collectorCoverage = nested
		}
		if _, ok := manifest["probe_plan"].(map[string]any); ok {
			c.CapabilitiesKnown = true
		}
		if cl, ok := collectorCoverage["claim"].(string); ok {
			if _, known := claimRank[cl]; known {
				c.CollectorClaim = cl
			} else {
				c.CollectorClaim = "unknown"
				c.KnownGaps = appendUnique(c.KnownGaps, "collector manifest contains an unsupported coverage claim")
			}
		}
		if kg, ok := collectorCoverage["known_gaps"].([]any); ok {
			for _, g := range kg {
				if s, ok := g.(string); ok {
					c.KnownGaps = appendUnique(c.KnownGaps, s)
				}
			}
		}
		if sources, ok := collectorCoverage["capture_sources"].([]any); ok {
			for _, source := range sources {
				if value, ok := source.(string); ok {
					c.CaptureSources = appendUnique(c.CaptureSources, value)
				}
			}
		}
		collectorUnknownTLS = jsonInt(collectorCoverage["unknown_tls_surfaces"])
		collectorUnparsed = jsonInt(collectorCoverage["unparsed_connections"])
		collectorUnknownEgress = jsonInt(collectorCoverage["unknown_egress"])
		collectorModelBypass = jsonInt(collectorCoverage["model_bypass_connections"])
		collectorDrops = int64(jsonInt(collectorCoverage["capture_drops"]))
		if surfaces, ok := collectorCoverage["observed_tls_surfaces"].(map[string]any); ok {
			for kind, count := range surfaces {
				c.TLSSurfaces = append(c.TLSSurfaces, map[string]any{"kind": kind, "count": jsonInt(count), "source": "collector_manifest"})
			}
		}
		if classes, ok := collectorCoverage["observed_egress_classes"].(map[string]any); ok {
			for class, count := range classes {
				mergeEgressCount(&c, class, jsonInt(count))
			}
		}
	}
	// attempts
	var noTerminal, bodyUnavail int
	if err := pool.QueryRow(ctx, `select count(*), count(*) filter (where terminal_state='unknown'), count(*) filter (where inference_id is null), count(*) filter (where normalized->>'body_unavailable' = 'true')
		from model_attempts where recording_id=$1`, rec).Scan(&c.TransportAttempts, &noTerminal, &c.UnattributedAttempts, &bodyUnavail); err != nil {
		return err
	}
	c.BodyUnavailable = bodyUnavail
	c.AllAttemptsHaveTerminalState = noTerminal == 0
	if err := pool.QueryRow(ctx, `select count(*), count(*) filter (where server_state='unresolved') from model_inferences where recording_id=$1`, rec).Scan(&c.LogicalInferences, &c.UnresolvedServerState); err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `select count(*) from model_attempts where recording_id=$1 and api_mode='unknown' and terminal_state <> 'error'`, rec).Scan(&c.UnparsedConnections); err != nil {
		return err
	}
	c.UnknownTLSSurfaces = max(c.UnknownTLSSurfaces, collectorUnknownTLS)
	c.UnparsedConnections = max(c.UnparsedConnections, collectorUnparsed)
	c.UnknownEgress = max(c.UnknownEgress, collectorUnknownEgress)
	c.UnknownEgress = max(c.UnknownEgress, c.ObservedEgressClasses["unknown_external"])
	c.ModelBypassConnections = max(c.ModelBypassConnections, collectorModelBypass)
	c.ModelBypassConnections = max(c.ModelBypassConnections, c.ObservedEgressClasses["model_bypass"])
	c.CaptureDrops = max(c.CaptureDrops, collectorDrops)
	var mb json.RawMessage
	var state string
	var alerts json.RawMessage
	if err := pool.QueryRow(ctx, `select missing_blobs, state, integrity_alerts from recordings where id=$1`, rec).Scan(&mb, &state, &alerts); err != nil {
		return err
	}
	var mbl []string
	_ = json.Unmarshal(mb, &mbl)
	c.MissingBlobs = len(mbl)
	var al []map[string]any
	_ = json.Unmarshal(alerts, &al)
	for _, a := range al {
		if a["kind"] == "auto_sealed_incomplete" {
			c.Incomplete = true
		}
	}
	var proofRaw json.RawMessage
	_ = pool.QueryRow(ctx, `select relation_revision, transport_proof from capture_runs where id=$1`, runIDOf(j)).Scan(&c.RelationRevision, &proofRaw)
	c.PlatformTransportProofStatus = "unavailable"
	if len(proofRaw) > 0 {
		var proof PlatformTransportProof
		if json.Unmarshal(proofRaw, &proof) == nil && validTransportProof(proof) {
			c.PlatformTransportProofStatus = proof.Status
			c.PlatformTransportProofVersion = proof.ProcessorVersion
			c.PlatformTransportProofVerified = proof.Verified
		} else {
			c.PlatformTransportProofStatus = "invalid"
			c.KnownGaps = appendUnique(c.KnownGaps, "platform transport proof is malformed or uses an unsupported version")
		}
	}
	assignCoverageClaim(&c, state)
	cb, _ := json.Marshal(c)
	if _, err := pool.Exec(ctx, `update recordings set coverage=$2, coverage_revision=coverage_revision+1, updated_at=now() where id=$1`, rec, cb); err != nil {
		return err
	}
	d.publish(ctx, j.ProjectID, "recording", rec, "coverage", c.RelationRevision)
	return nil
}

// assignCoverageClaim deliberately treats absence of observed loss as
// insufficient evidence of completeness. Only the platform-owned, exact-version
// task-egress decoder and payload agreement stage can set the proof gate.
func assignCoverageClaim(c *Coverage, state string) {
	c.Claim = "best-effort"
	if !c.CapabilitiesKnown || c.UnknownTLSSurfaces > 0 || c.Incomplete || c.CollectorClaim == "unknown" {
		c.Claim = "unknown"
		return
	}
	if state != "sealed" {
		c.KnownGaps = appendUnique(c.KnownGaps, "recording still open")
		return
	}
	if !c.PlatformTransportProofVerified {
		c.KnownGaps = appendUnique(c.KnownGaps, "platform transport proof is unavailable; zero observed gaps is not proof of complete capture")
		return
	}
	if c.UnparsedConnections != 0 || c.CaptureDrops != 0 || c.UnknownEgress != 0 || c.ModelBypassConnections != 0 || !c.AllAttemptsHaveTerminalState || c.MissingBlobs != 0 {
		return
	}
	c.Claim = "transport-complete"
	if c.BodyUnavailable == 0 && c.UnattributedAttempts == 0 && c.TransportAttempts > 0 {
		c.Claim = "client-complete"
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func mergeEgressCount(c *Coverage, class string, count int) {
	if c.ObservedEgressClasses == nil {
		c.ObservedEgressClasses = map[string]int{}
	}
	if !knownEgressClass(class) {
		class = "unknown_external"
	}
	count = max(count, 0)
	if count > c.ObservedEgressClasses[class] {
		c.ObservedEgressClasses[class] = count
	}
}

func knownEgressClass(class string) bool {
	switch class {
	case "model_recorder", "model_bypass", "local", "auth", "telemetry", "update", "other", "unknown_external":
		return true
	default:
		return false
	}
}

func jsonInt(value any) int {
	maximum := int(^uint(0) >> 1)
	switch value := value.(type) {
	case float64:
		if value <= 0 {
			return 0
		}
		if value >= float64(maximum) {
			return maximum
		}
		return int(value)
	case int:
		if value < 0 {
			return 0
		}
		return value
	case int64:
		if value <= 0 {
			return 0
		}
		if value >= int64(maximum) {
			return maximum
		}
		return int(value)
	default:
		return 0
	}
}
