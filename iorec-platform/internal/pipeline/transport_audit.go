package pipeline

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
)

const (
	platformProofSchema     = 1
	platformProofBoundary   = "target-network-namespace-ip-transport"
	pcapMediaType           = "application/vnd.tcpdump.pcap"
	tlsSecretsMediaType     = "application/x-nss-key-log"
	maxAuditArtifactBytes   = int64(1 << 30)
	maxAuditBlobBytes       = int64(64 << 20)
	maxAuditArtifactRecords = 250_000
	maxAuditProxyEvents     = 1_000_000
	maxAuditAttempts        = 100_000
	maxDecodedRows          = 10_000_000
	maxDecodedStreams       = 100_000
	maxTSharkBytes          = int64(128 << 20)
	maxTSharkVersionBytes   = int64(64 << 10)
	maxTSharkStderrBytes    = int64(64 << 10)
	maxTSharkLineBytes      = 129 << 20
	maxTSharkEKLineBytes    = 264 << 20
	maxTSharkStdoutBytes    = int64(4 << 30)
	maxMethodBytes          = 64
	maxPathBytes            = 16 << 10
	tsharkColumnCount       = 22
)

var tsharkFields = []string{
	"frame.number", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport",
	"ip.dst", "ipv6.dst", "tcp.dstport", "http.request.method",
	"http.request.uri", "http.response.code", "http.file_data",
	"http2.streamid", "http2.type", "http2.length", "http2.flags",
	"http2.headers.method", "http2.headers.path", "http2.headers.status",
	"http2.data.data", "http2.pad_length", "tls.record.content_type",
}

// TransportDecoder is a platform-owned packet decoder. Implementations receive
// private, bounded temporary files and must return independently reconstructed
// HTTP streams; collector-supplied reports never satisfy this interface.
type TransportDecoder interface {
	DecodeTransport(context.Context, string, string, string) (*transportDecodeResult, error)
	Identity() DecoderIdentity
}

// DecoderIdentity is persisted with every proof so an operator can bind a
// verdict to the exact decoder executable.
type DecoderIdentity struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type ProofGap struct {
	Reason      string `json:"reason"`
	Occurrences int64  `json:"occurrences"`
}

// PlatformTransportProof is generated only by the platform worker from raw
// event/blob objects and a locally configured decoder.
type PlatformTransportProof struct {
	SchemaVersion         int              `json:"schema_version"`
	Status                string           `json:"status"`
	Verified              bool             `json:"verified"`
	CompletenessBoundary  string           `json:"completeness_boundary"`
	ProcessorVersion      string           `json:"processor_version"`
	GeneratedAt           time.Time        `json:"generated_at"`
	Decoder               *DecoderIdentity `json:"decoder,omitempty"`
	SourceBoundaryOK      bool             `json:"source_boundary_verified"`
	PcapRecords           int64            `json:"pcap_records"`
	PcapBytes             int64            `json:"pcap_bytes"`
	TLSKeyRecords         int64            `json:"tls_key_records"`
	TLSKeyBytes           int64            `json:"tls_key_bytes"`
	DecodedRows           int64            `json:"decoded_rows"`
	DecodedStreams        int64            `json:"decoded_streams"`
	TLSDecryptedStreams   int64            `json:"tls_decrypted_streams"`
	ProxyAttempts         int64            `json:"proxy_attempts"`
	ProxyAttemptsEligible int64            `json:"proxy_attempts_eligible"`
	MatchedAttempts       int64            `json:"matched_attempts"`
	MissingFromWire       int64            `json:"missing_from_wire"`
	ExtraOnWire           int64            `json:"extra_on_wire"`
	AmbiguousGroups       int64            `json:"ambiguous_signature_groups"`
	PayloadDiffPassed     bool             `json:"payload_diff_passed"`
	Gaps                  []ProofGap       `json:"gaps"`
}

type transportDecodeResult struct {
	Rows        int64
	Streams     []decodedStream
	Gaps        map[string]int64
	StderrBytes int64
}

type decodedStream struct {
	Protocol        string
	TCPStream       uint64
	HTTP2StreamID   uint32
	Method          string
	Path            string
	Status          uint16
	Request         bodyDigest
	Response        bodyDigest
	TLSDecrypted    bool
	EligibleForDiff bool
	Gaps            []string
}

type bodyDigest struct {
	Bytes  int64
	SHA256 string
	Chunks int64
}

type artifactSummary struct {
	Records int64
	Bytes   int64
}

type sourceBoundary struct {
	OK             bool
	TransparentTLS bool
	Cleartext      bool
	Gaps           map[string]int64
}

type comparison struct {
	ProxyAttempts int64
	Eligible      int64
	Matched       int64
	Missing       int64
	Extra         int64
	Ambiguous     int64
	UnknownClass  int64
}

var errSensitiveEvidenceUnavailable = errors.New("sensitive evidence unavailable")

// TransportAudit independently reconstructs task-egress streams and compares
// their exact body digests with platform-fetched proxy evidence.
func (d *Deps) TransportAudit(ctx context.Context, j *jobs.Job) error {
	run := runIDOf(j)
	if run == "" {
		return fmt.Errorf("transport audit job has no capture_run_id")
	}
	proof := PlatformTransportProof{
		SchemaVersion:        platformProofSchema,
		Status:               "unavailable",
		CompletenessBoundary: platformProofBoundary,
		ProcessorVersion:     TransportAuditVersion,
		GeneratedAt:          time.Now().UTC(),
		Gaps:                 []ProofGap{},
	}
	if d.TransportDecoder == nil {
		proof.Gaps = []ProofGap{{Reason: "platform_transport_decoder_unavailable", Occurrences: 1}}
	} else {
		identity := d.TransportDecoder.Identity()
		proof.Decoder = &identity
		computed, err := d.computeTransportProof(ctx, j.ProjectID, run, proof)
		switch {
		case err == nil:
			proof = computed
		case errors.Is(err, errSensitiveEvidenceUnavailable):
			proof.Status = "unavailable"
			proof.Gaps = []ProofGap{{Reason: "sensitive_transport_evidence_not_uploaded", Occurrences: 1}}
		default:
			proof.Status = "failed"
			proof.Gaps = []ProofGap{{Reason: classifyTransportAuditError(err), Occurrences: 1}}
		}
	}
	return d.persistTransportProof(ctx, j, proof)
}

func classifyTransportAuditError(err error) string {
	for _, item := range []struct {
		match, reason string
	}{
		{"decoder", "platform_transport_decoder_failed"},
		{"tshark", "platform_transport_decoder_failed"},
		{"blob", "platform_transport_blob_validation_failed"},
		{"pcap", "platform_pcap_validation_failed"},
		{"TLS key", "platform_tls_key_validation_failed"},
		{"proxy", "platform_proxy_evidence_validation_failed"},
	} {
		if strings.Contains(err.Error(), item.match) {
			return item.reason
		}
	}
	return "platform_transport_audit_failed"
}

func (d *Deps) persistTransportProof(ctx context.Context, j *jobs.Job, proof PlatformTransportProof) error {
	encoded, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	run := runIDOf(j)
	return d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, "iorec-transport-proof:"+run); err != nil {
			return err
		}
		var owner uuid.UUID
		if err := tx.QueryRow(ctx, `select project_id from capture_runs where id=$1 for update`, run).Scan(&owner); err != nil {
			return err
		}
		if owner != j.ProjectID {
			return fmt.Errorf("transport audit project ownership mismatch")
		}
		if _, err := tx.Exec(ctx, `update capture_runs set transport_proof=$2::jsonb, transport_proof_revision=transport_proof_revision+1 where id=$1`, run, encoded); err != nil {
			return err
		}
		recordings, err := scanStrings(tx.Query(ctx, `select id from recordings where capture_run_id=$1 order by segment_no`, run))
		if err != nil {
			return err
		}
		for _, recording := range recordings {
			if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{ProjectID: j.ProjectID, Type: jobs.TypeCoverage, RecordingID: recording, CaptureRunID: run, InputRef: map[string]any{"transport_proof_generated_at": proof.GeneratedAt}, ProcessorVersion: CoverageVersion, Priority: 4}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Deps) computeTransportProof(ctx context.Context, projectID uuid.UUID, run string, proof PlatformTransportProof) (PlatformTransportProof, error) {
	boundary, err := d.verifySourceBoundary(ctx, run)
	if err != nil {
		return proof, err
	}
	proof.SourceBoundaryOK = boundary.OK
	temporary, err := os.MkdirTemp("", "iorec-platform-transport-*")
	if err != nil {
		return proof, err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return proof, err
	}
	pcapPath := filepath.Join(temporary, "capture.pcap")
	keysPath := filepath.Join(temporary, "tls.keys")
	pcap, err := d.materializeArtifact(ctx, projectID, run, pcapMediaType, pcapPath)
	if err != nil {
		return proof, err
	}
	keys, err := d.materializeArtifact(ctx, projectID, run, tlsSecretsMediaType, keysPath)
	if err != nil && !errors.Is(err, errSensitiveEvidenceUnavailable) {
		return proof, err
	}
	if errors.Is(err, errSensitiveEvidenceUnavailable) {
		if !boundary.Cleartext {
			return proof, err
		}
		keys = artifactSummary{}
		if writeErr := os.WriteFile(keysPath, nil, 0o600); writeErr != nil {
			return proof, writeErr
		}
	}
	proof.PcapRecords, proof.PcapBytes = pcap.Records, pcap.Bytes
	proof.TLSKeyRecords, proof.TLSKeyBytes = keys.Records, keys.Bytes
	decoded, err := d.TransportDecoder.DecodeTransport(ctx, pcapPath, keysPath, temporary)
	if err != nil {
		return proof, fmt.Errorf("platform transport decoder: %w", err)
	}
	proof.DecodedRows = decoded.Rows
	proof.DecodedStreams = int64(len(decoded.Streams))
	for _, stream := range decoded.Streams {
		if stream.TLSDecrypted {
			proof.TLSDecryptedStreams++
		}
	}
	attempts, proxyGaps, err := d.collectProxyAttempts(ctx, projectID, run)
	if err != nil {
		return proof, err
	}
	comp := compareTransportEvidence(attempts, decoded.Streams)
	proof.ProxyAttempts = comp.ProxyAttempts
	proof.ProxyAttemptsEligible = comp.Eligible
	proof.MatchedAttempts = comp.Matched
	proof.MissingFromWire = comp.Missing
	proof.ExtraOnWire = comp.Extra
	proof.AmbiguousGroups = comp.Ambiguous
	proof.PayloadDiffPassed = comp.ProxyAttempts > 0 && comp.ProxyAttempts == comp.Eligible && comp.Missing == 0 && comp.Extra == 0
	gaps := boundary.Gaps
	mergeProofGaps(gaps, decoded.Gaps)
	mergeProofGaps(gaps, proxyGaps)
	if decoded.StderrBytes > 0 {
		addProofGap(gaps, "tshark_diagnostic_output", 1)
	}
	if len(decoded.Streams) == 0 {
		addProofGap(gaps, "no_http_streams_decoded", 1)
	}
	if comp.ProxyAttempts == 0 {
		addProofGap(gaps, "no_proxy_attempts_for_diff", 1)
	}
	if comp.UnknownClass > 0 {
		addProofGap(gaps, "proxy_attempt_traffic_class_unknown", comp.UnknownClass)
	}
	if comp.ProxyAttempts-comp.Eligible > 0 {
		addProofGap(gaps, "proxy_attempt_ineligible_for_diff", comp.ProxyAttempts-comp.Eligible)
	}
	if comp.Missing > 0 {
		addProofGap(gaps, "proxy_attempt_missing_from_wire", comp.Missing)
	}
	if comp.Extra > 0 {
		addProofGap(gaps, "decoded_wire_stream_without_proxy_match", comp.Extra)
	}
	if comp.Ambiguous > 0 {
		addProofGap(gaps, "ambiguous_payload_signature_group", comp.Ambiguous)
	}
	if boundary.TransparentTLS && proof.TLSDecryptedStreams == 0 {
		addProofGap(gaps, "no_tls_streams_decrypted", 1)
	}
	proof.Gaps = sortedProofGaps(gaps)
	proof.Verified = proof.SourceBoundaryOK && proof.PayloadDiffPassed && len(proof.Gaps) == 0
	if proof.Verified {
		proof.Status = "verified"
	} else {
		proof.Status = "incomplete"
	}
	return proof, nil
}

func addProofGap(gaps map[string]int64, reason string, occurrences int64) {
	if occurrences < 1 {
		occurrences = 1
	}
	gaps[reason] += occurrences
}

func mergeProofGaps(destination, source map[string]int64) {
	for reason, occurrences := range source {
		addProofGap(destination, reason, occurrences)
	}
}

func sortedProofGaps(gaps map[string]int64) []ProofGap {
	reasons := make([]string, 0, len(gaps))
	for reason := range gaps {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	result := make([]ProofGap, 0, len(reasons))
	for _, reason := range reasons {
		result = append(result, ProofGap{Reason: reason, Occurrences: gaps[reason]})
	}
	return result
}

func validTransportProof(proof PlatformTransportProof) bool {
	if proof.SchemaVersion != platformProofSchema || proof.CompletenessBoundary != platformProofBoundary || proof.ProcessorVersion != TransportAuditVersion || proof.GeneratedAt.IsZero() {
		return false
	}
	switch proof.Status {
	case "unavailable", "failed", "incomplete", "verified":
	default:
		return false
	}
	if proof.Verified != (proof.Status == "verified") || len(proof.Gaps) > 256 {
		return false
	}
	previousReason := ""
	for _, gap := range proof.Gaps {
		if gap.Occurrences < 1 || !validGapReason(gap.Reason) || (previousReason != "" && gap.Reason <= previousReason) {
			return false
		}
		previousReason = gap.Reason
	}
	counts := []int64{
		proof.PcapRecords, proof.PcapBytes, proof.TLSKeyRecords, proof.TLSKeyBytes,
		proof.DecodedRows, proof.DecodedStreams, proof.TLSDecryptedStreams,
		proof.ProxyAttempts, proof.ProxyAttemptsEligible, proof.MatchedAttempts,
		proof.MissingFromWire, proof.ExtraOnWire, proof.AmbiguousGroups,
	}
	for _, count := range counts {
		if count < 0 {
			return false
		}
	}
	if proof.TLSDecryptedStreams > proof.DecodedStreams || proof.ProxyAttemptsEligible > proof.ProxyAttempts || proof.MatchedAttempts > proof.ProxyAttemptsEligible {
		return false
	}
	if (proof.TLSKeyRecords == 0) != (proof.TLSKeyBytes == 0) {
		return false
	}
	if !proof.Verified {
		return len(proof.Gaps) > 0
	}
	if proof.Decoder == nil || !boundedText(proof.Decoder.Kind, 64) || !boundedText(proof.Decoder.Path, 4096) || !filepath.IsAbs(proof.Decoder.Path) || !boundedText(proof.Decoder.Version, int(maxTSharkVersionBytes)) || len(proof.Decoder.SHA256) != sha256.Size*2 {
		return false
	}
	if _, err := hex.DecodeString(proof.Decoder.SHA256); err != nil {
		return false
	}
	return proof.SourceBoundaryOK && proof.PayloadDiffPassed && len(proof.Gaps) == 0 &&
		proof.PcapRecords > 0 && proof.PcapBytes > 0 && proof.DecodedRows > 0 && proof.DecodedStreams > 0 &&
		proof.ProxyAttempts > 0 && proof.ProxyAttemptsEligible == proof.ProxyAttempts &&
		proof.MatchedAttempts == proof.ProxyAttempts && proof.MissingFromWire == 0 && proof.ExtraOnWire == 0 && proof.AmbiguousGroups == 0
}

func validGapReason(reason string) bool {
	if reason == "" || len(reason) > 128 {
		return false
	}
	for _, character := range reason {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func (d *Deps) verifySourceBoundary(ctx context.Context, run string) (sourceBoundary, error) {
	events, err := d.loadRunEvents(ctx, run, `and e.source='runner' and e.event in
		('task_network_isolation_configured','pcap_capture_started','task_network_target_confined',
		 'task_network_target_window_closed','task_network_isolation_finished','pcap_capture_finished',
		 'task_network_isolation_error','task_network_target_window_error','pcap_capture_error',
		 'transparent_interception_prepared')`)
	if err != nil {
		return sourceBoundary{Gaps: make(map[string]int64)}, err
	}
	return verifySourceBoundaryEvents(events), nil
}

func verifySourceBoundaryEvents(events []rawEvent) sourceBoundary {
	result := sourceBoundary{Gaps: make(map[string]int64)}
	var configured, pcapStarted, confined, windowClosed, networkFinished, pcapFinished int
	var transparentPrepared int
	transparentTLSSet := false
	policyMode := ""
	pcapPolicyMode := ""
	for _, event := range events {
		var payload map[string]any
		if len(event.Payload) > 0 && json.Unmarshal(event.Payload, &payload) != nil {
			addProofGap(result.Gaps, "task_egress_boundary_payload_invalid", 1)
			continue
		}
		switch event.Event {
		case "task_network_isolation_configured":
			configured++
			mode, _ := payload["policy_mode"].(string)
			if policyMode == "" {
				policyMode = mode
			}
			if (mode != "proxy_only" && mode != "transparent") || payload["default_egress_policy"] != "drop" || payload["dns_enabled"] != false || payload["ipv6_enabled"] != false {
				addProofGap(result.Gaps, "task_egress_policy_not_fail_closed", 1)
			}
		case "pcap_capture_started":
			pcapStarted++
			if payload["scope"] != "task_egress" {
				addProofGap(result.Gaps, "packet_capture_scope_not_task_egress", 1)
			}
			pcapPolicyMode, _ = payload["egress_policy"].(string)
		case "task_network_target_confined":
			confined++
			if event.TerminalState != "complete" || payload["capabilities_zero"] != true || payload["bounding_capabilities_zero"] != true || payload["no_new_privileges"] != true {
				addProofGap(result.Gaps, "target_confinement_not_verified", 1)
			}
		case "task_network_target_window_closed":
			windowClosed++
			if event.TerminalState != "complete" {
				addProofGap(result.Gaps, "task_egress_target_window_not_closed", 1)
			}
		case "task_network_isolation_finished":
			networkFinished++
			if event.TerminalState != "complete" || !taskNetworkReportComplete(payload, policyMode) {
				addProofGap(result.Gaps, "task_egress_shutdown_not_verified", 1)
			}
		case "pcap_capture_finished":
			pcapFinished++
			if event.TerminalState != "complete" || !pcapReportComplete(payload) {
				addProofGap(result.Gaps, "packet_capture_not_complete", 1)
			}
		case "transparent_interception_prepared":
			transparentPrepared++
			if downstreamTLS, ok := payload["downstream_tls"].(bool); ok {
				result.TransparentTLS = downstreamTLS
				transparentTLSSet = true
			} else {
				addProofGap(result.Gaps, "transparent_interception_payload_invalid", 1)
			}
		case "task_network_isolation_error", "task_network_target_window_error", "pcap_capture_error":
			addProofGap(result.Gaps, "task_egress_boundary_error", 1)
		}
	}
	if pcapPolicyMode == "" || pcapPolicyMode != policyMode {
		addProofGap(result.Gaps, "pcap_policy_mode_mismatch", 1)
	}
	wantTransparentPrepared := 0
	if policyMode == "transparent" {
		wantTransparentPrepared = 1
	}
	if transparentPrepared != wantTransparentPrepared || (wantTransparentPrepared == 1 && !transparentTLSSet) {
		addProofGap(result.Gaps, "transparent_interception_evidence_not_unique", 1)
	}
	for reason, count := range map[string]int{
		"task_egress_configuration_not_unique": configured,
		"task_egress_pcap_start_not_unique":    pcapStarted,
		"target_confinement_not_unique":        confined,
		"target_window_close_not_unique":       windowClosed,
		"task_egress_finish_not_unique":        networkFinished,
		"pcap_finish_not_unique":               pcapFinished,
	} {
		if count != 1 {
			addProofGap(result.Gaps, reason, 1)
		}
	}
	result.Cleartext = policyMode == "proxy_only" || (policyMode == "transparent" && transparentPrepared == 1 && transparentTLSSet && !result.TransparentTLS)
	result.OK = len(result.Gaps) == 0
	return result
}

func taskNetworkReportComplete(payload map[string]any, policyMode string) bool {
	for _, field := range []string{
		"firewall_verified_at_target_start", "firewall_verified_at_target_end",
		"firewall_verified_at_stop", "ipv6_disabled_at_start", "ipv6_disabled_at_stop",
	} {
		if payload[field] != true {
			return false
		}
	}
	if mode, _ := payload["policy_mode"].(string); mode != policyMode {
		return false
	}
	if policyMode == "transparent" && payload["hosts_snapshot_verified_at_start"] != true {
		return false
	}
	helperExited, exitedOK := jsonBoolean(payload, "helper_exited_before_stop")
	helperForced, forcedOK := jsonBoolean(payload, "helper_forced_kill")
	exitOK, exitFieldOK := jsonBoolean(payload, "helper_exit_success")
	if !exitedOK || !forcedOK || !exitFieldOK || helperExited || helperForced || !zeroJSONInteger(payload, "helper_stdout_omitted") || !zeroJSONInteger(payload, "helper_stderr_omitted") {
		return false
	}
	signalValue, signalPresent, signalValid := optionalJSONInteger(payload, "helper_termination_signal")
	if !signalValid || (!exitOK && (!signalPresent || signalValue != int64(syscall.SIGTERM))) {
		return false
	}
	post, _ := payload["post_target_firewall"].(map[string]any)
	if post == nil {
		return false
	}
	for _, field := range []string{"loopback_packets", "proxy_packets", "transparent_packets", "denied_packets"} {
		if !zeroJSONInteger(post, field) {
			return false
		}
	}
	return true
}

func pcapReportComplete(payload map[string]any) bool {
	limitReached, limitOK := jsonBoolean(payload, "limit_reached")
	exitSuccess, exitOK := jsonBoolean(payload, "exit_success")
	forcedKill, forcedOK := jsonBoolean(payload, "forced_kill")
	return limitOK && exitOK && forcedOK && !limitReached && exitSuccess && !forcedKill && zeroJSONInteger(payload, "packets_dropped") && zeroJSONInteger(payload, "packets_missed") && zeroJSONInteger(payload, "stderr_bytes_omitted")
}

func jsonInteger(value any) int64 {
	parsed, _ := jsonIntegerValue(value)
	return parsed
}

func jsonIntegerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < math.MinInt64 || number > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil
	case int64:
		return number, true
	case int:
		return int64(number), true
	default:
		return 0, false
	}
}

func zeroJSONInteger(object map[string]any, field string) bool {
	value, ok := object[field]
	if !ok {
		return false
	}
	parsed, ok := jsonIntegerValue(value)
	return ok && parsed == 0
}

func optionalJSONInteger(object map[string]any, field string) (value int64, present, valid bool) {
	raw, exists := object[field]
	if !exists {
		return 0, false, false
	}
	if raw == nil {
		return 0, false, true
	}
	parsed, ok := jsonIntegerValue(raw)
	return parsed, ok, ok
}

func jsonBoolean(object map[string]any, field string) (bool, bool) {
	value, ok := object[field]
	if !ok {
		return false, false
	}
	parsed, ok := value.(bool)
	return parsed, ok
}

func (d *Deps) materializeArtifact(ctx context.Context, projectID uuid.UUID, run, mediaType, output string) (artifactSummary, error) {
	result := artifactSummary{}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, err
	}
	defer file.Close()
	rows, err := d.DB.Pool.Query(ctx, `select e.source, e.event, e.payload_sha256, e.payload_size, e.raw_truncated, e.payload
		from recording_events e join recordings r on r.id=e.recording_id
		where r.capture_run_id=$1 and e.raw_media_type=$2 order by e.seq, e.recording_id limit $3`, run, mediaType, maxAuditArtifactRecords+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	expectedPcapChunk := int64(1)
	expectedOffset := int64(0)
	for rows.Next() {
		if result.Records == maxAuditArtifactRecords {
			return result, fmt.Errorf("%s artifact record limit exceeded", artifactName(mediaType))
		}
		var source, event string
		var digest []byte
		var size *int64
		var truncated bool
		var payload json.RawMessage
		if err := rows.Scan(&source, &event, &digest, &size, &truncated, &payload); err != nil {
			return result, err
		}
		if size == nil || *size < 0 || *size > maxAuditBlobBytes || len(digest) != sha256.Size || truncated {
			return result, fmt.Errorf("%s blob reference is invalid", artifactName(mediaType))
		}
		if result.Bytes > maxAuditArtifactBytes-*size {
			return result, fmt.Errorf("%s artifact byte limit exceeded", artifactName(mediaType))
		}
		blob, err := d.readVerifiedBlob(ctx, projectID, digest, *size)
		if err != nil {
			return result, err
		}
		if mediaType == pcapMediaType {
			if source != "pcap" || event != "pcap_capture_chunk" {
				return result, fmt.Errorf("pcap media type appears on an unexpected event")
			}
			var metadata struct {
				ChunkSequence int64 `json:"chunk_sequence"`
				Offset        int64 `json:"offset"`
				Bytes         int64 `json:"bytes"`
			}
			if json.Unmarshal(payload, &metadata) != nil || metadata.ChunkSequence != expectedPcapChunk || metadata.Offset != expectedOffset || metadata.Bytes != *size {
				return result, fmt.Errorf("pcap chunk sequence or offset is invalid")
			}
			expectedPcapChunk++
			expectedOffset += *size
		} else {
			if source != "tls-keylog" || event != "tls_key_log_secret" || !validTLSKeyRecord(blob) {
				return result, fmt.Errorf("TLS key record is invalid")
			}
		}
		if _, err := file.Write(blob); err != nil {
			return result, err
		}
		if mediaType == tlsSecretsMediaType {
			if _, err := file.Write([]byte{'\n'}); err != nil {
				return result, err
			}
		}
		result.Records++
		result.Bytes += *size
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if result.Records == 0 {
		return result, errSensitiveEvidenceUnavailable
	}
	if err := file.Sync(); err != nil {
		return result, err
	}
	return result, nil
}

func artifactName(mediaType string) string {
	if mediaType == pcapMediaType {
		return "pcap"
	}
	return "TLS key"
}

func validTLSKeyRecord(record []byte) bool {
	if len(record) == 0 || len(record) > 4096 || strings.ContainsAny(string(record), "\r\n\x00") {
		return false
	}
	fields := strings.Fields(string(record))
	if len(fields) != 3 || len(fields[0]) == 0 || len(fields[0]) > 64 {
		return false
	}
	for _, r := range fields[0] {
		if !(unicode.IsUpper(r) || unicode.IsDigit(r) || r == '_') || r > unicode.MaxASCII {
			return false
		}
	}
	return validHexRange(fields[1], 64, 128) && validHexRange(fields[2], 32, 512)
}

func validHexRange(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || len(value)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (d *Deps) readVerifiedBlob(ctx context.Context, projectID uuid.UUID, digest []byte, expectedSize int64) ([]byte, error) {
	var key string
	var size int64
	err := d.DB.Pool.QueryRow(ctx, `select object_key, size from blobs where project_id=$1 and sha256=$2`, projectID, digest).Scan(&key, &size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errSensitiveEvidenceUnavailable
	}
	if err != nil {
		return nil, err
	}
	if size != expectedSize || size < 0 || size > maxAuditBlobBytes {
		return nil, fmt.Errorf("blob catalog size mismatch")
	}
	reader, err := d.Obj.Get(ctx, key)
	if errors.Is(err, objstore.ErrNotFound) {
		return nil, fmt.Errorf("blob object is missing")
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	bytes, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(bytes)) != size {
		return nil, fmt.Errorf("blob object length mismatch")
	}
	actual := sha256.Sum256(bytes)
	if subtle.ConstantTimeCompare(actual[:], digest) != 1 {
		return nil, fmt.Errorf("blob object digest mismatch")
	}
	return bytes, nil
}

type bodyAccumulator struct {
	digest hash.Hash
	bytes  int64
	chunks int64
}

type websocketBodyAccumulator struct {
	digest   hash.Hash
	bytes    int64
	messages int64
}

func (body *websocketBodyAccumulator) appendMessage(opcode byte, payload []byte) error {
	if opcode != 1 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10 {
		return fmt.Errorf("unsupported WebSocket message opcode")
	}
	if int64(len(payload)) > maxAuditArtifactBytes-body.bytes {
		return fmt.Errorf("WebSocket payload byte limit exceeded")
	}
	if body.digest == nil {
		body.digest = sha256.New()
	}
	if _, err := body.digest.Write([]byte("iorec-websocket-message-v1\x00")); err != nil {
		return err
	}
	if _, err := body.digest.Write([]byte{opcode}); err != nil {
		return err
	}
	length := uint64(len(payload))
	lengthBytes := [8]byte{
		byte(length >> 56), byte(length >> 48), byte(length >> 40), byte(length >> 32),
		byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length),
	}
	if _, err := body.digest.Write(lengthBytes[:]); err != nil {
		return err
	}
	if _, err := body.digest.Write(payload); err != nil {
		return err
	}
	body.bytes += int64(len(payload))
	body.messages++
	return nil
}

func (body *websocketBodyAccumulator) finish() bodyDigest {
	digest := sha256.Sum256(nil)
	if body.digest != nil {
		copy(digest[:], body.digest.Sum(nil))
	}
	return bodyDigest{Bytes: body.bytes, SHA256: hex.EncodeToString(digest[:]), Chunks: body.messages}
}

func (body *bodyAccumulator) appendBytes(value []byte) error {
	if body.digest == nil {
		body.digest = sha256.New()
	}
	if int64(len(value)) > maxAuditArtifactBytes-body.bytes {
		return fmt.Errorf("decoded body byte limit exceeded")
	}
	if _, err := body.digest.Write(value); err != nil {
		return err
	}
	body.bytes += int64(len(value))
	body.chunks++
	return nil
}

func (body *bodyAccumulator) appendHex(value string) (int64, error) {
	buffer := make([]byte, 64<<10)
	used := 0
	var high byte
	hasHigh := false
	var total int64
	flush := func() error {
		if used == 0 {
			return nil
		}
		if body.digest == nil {
			body.digest = sha256.New()
		}
		_, err := body.digest.Write(buffer[:used])
		used = 0
		return err
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == ':' || character == ' ' || character == '\r' || character == '\n' {
			continue
		}
		nibble, ok := hexNibble(character)
		if !ok {
			return 0, fmt.Errorf("tshark emitted a non-hexadecimal body field")
		}
		if !hasHigh {
			high, hasHigh = nibble, true
			continue
		}
		buffer[used] = high<<4 | nibble
		used++
		total++
		hasHigh = false
		if used == len(buffer) {
			if err := flush(); err != nil {
				return 0, err
			}
		}
	}
	if hasHigh {
		return 0, fmt.Errorf("tshark emitted an odd-length body field")
	}
	if body.bytes > maxAuditArtifactBytes-total {
		return 0, fmt.Errorf("decoded body byte limit exceeded")
	}
	if err := flush(); err != nil {
		return 0, err
	}
	if total > 0 {
		body.bytes += total
		body.chunks++
	}
	return total, nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func (body *bodyAccumulator) finish() bodyDigest {
	digest := sha256.Sum256(nil)
	if body.digest != nil {
		copy(digest[:], body.digest.Sum(nil))
	}
	return bodyDigest{Bytes: body.bytes, SHA256: hex.EncodeToString(digest[:]), Chunks: body.chunks}
}

type proxyAttempt struct {
	method, path       string
	status             uint16
	request, response  bodyAccumulator
	websocketRequest   websocketBodyAccumulator
	websocketResponse  websocketBodyAccumulator
	nextRequestChunk   int64
	nextResponseChunk  int64
	nextWSRequest      int64
	nextWSResponse     int64
	wsRequestMessages  int64
	wsResponseMessages int64
	requestFinished    bool
	attemptFinished    bool
	websocketTerminal  string
	attemptTerminal    string
	websocket          bool
	modelTraffic       int
	requestStarted     int
	responseStarted    int
	requestEnded       int
	responseEnded      int
	websocketStarted   int
	websocketEnded     int
	gaps               map[string]struct{}
}

func newProxyAttempt() *proxyAttempt {
	return &proxyAttempt{nextRequestChunk: 1, nextResponseChunk: 1, nextWSRequest: 1, nextWSResponse: 1, gaps: make(map[string]struct{})}
}

func (d *Deps) collectProxyAttempts(ctx context.Context, projectID uuid.UUID, run string) (map[string]*proxyAttempt, map[string]int64, error) {
	rows, err := d.DB.Pool.Query(ctx, `select e.event, coalesce(e.attempt_id,''), e.payload, e.payload_sha256, e.payload_size, e.raw_truncated, coalesce(e.terminal_state,'')
		from recording_events e join recordings r on r.id=e.recording_id
		where r.capture_run_id=$1 and e.source='proxy' and e.event in
		('transport_request_started','transport_response_started','request_body_chunk',
		 'response_body_chunk','request_body_finished','transport_attempt_finished',
		 'websocket_connection_started','websocket_frame','websocket_connection_finished')
		order by e.seq, e.recording_id limit $2`, run, maxAuditProxyEvents+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	attempts := make(map[string]*proxyAttempt)
	globalGaps := make(map[string]int64)
	eventCount := 0
	for rows.Next() {
		eventCount++
		if eventCount > maxAuditProxyEvents {
			return nil, nil, fmt.Errorf("proxy event limit exceeded")
		}
		var event, attemptID, terminal string
		var payload json.RawMessage
		var digest []byte
		var size *int64
		var truncated bool
		if err := rows.Scan(&event, &attemptID, &payload, &digest, &size, &truncated, &terminal); err != nil {
			return nil, nil, err
		}
		if attemptID == "" {
			addProofGap(globalGaps, "proxy_event_attempt_id_missing", 1)
			continue
		}
		attempt := attempts[attemptID]
		if attempt == nil {
			if len(attempts) == maxAuditAttempts {
				return nil, nil, fmt.Errorf("proxy attempt limit exceeded")
			}
			attempt = newProxyAttempt()
			attempts[attemptID] = attempt
		}
		var metadata map[string]any
		if len(payload) > 0 && json.Unmarshal(payload, &metadata) != nil {
			attempt.gaps["proxy_metadata_invalid"] = struct{}{}
			continue
		}
		switch event {
		case "transport_request_started":
			attempt.requestStarted++
			if attempt.requestStarted == 1 {
				attempt.method, _ = metadata["method"].(string)
				attempt.path = proxyPath(metadata["uri"])
				switch metadata["traffic_class"] {
				case "model":
					attempt.modelTraffic = 1
				case "other":
					attempt.modelTraffic = -1
				default:
					attempt.modelTraffic = 0
				}
				protocol, _ := metadata["protocol"].(string)
				attempt.websocket = protocol == "websocket"
				if attempt.websocket {
					attempt.requestFinished = true
				}
			}
		case "transport_response_started":
			attempt.responseStarted++
			if attempt.responseStarted == 1 {
				status := jsonInteger(metadata["status"])
				if status > 0 && status <= 65535 {
					attempt.status = uint16(status)
				}
			}
		case "websocket_connection_started":
			attempt.websocketStarted++
			attempt.responseStarted++
			if attempt.websocketStarted == 1 {
				status := jsonInteger(metadata["status"])
				if status > 0 && status <= 65535 {
					attempt.status = uint16(status)
				}
			}
		case "websocket_frame":
			if err := d.appendProxyWebSocketFrame(ctx, projectID, attempt, metadata, digest, size, truncated); err != nil {
				return nil, nil, err
			}
		case "websocket_connection_finished":
			attempt.websocketEnded++
			attempt.websocketTerminal = terminal
			if jsonInteger(metadata["client_messages"]) != attempt.wsRequestMessages || jsonInteger(metadata["upstream_messages"]) != attempt.wsResponseMessages {
				attempt.gaps["proxy_websocket_message_count_mismatch"] = struct{}{}
			}
			captureFailed, ok := metadata["capture_failed"].(bool)
			if !ok || captureFailed {
				attempt.gaps["proxy_websocket_capture_incomplete"] = struct{}{}
			}
			if attempt.websocketTerminal == "" {
				attempt.gaps["proxy_websocket_terminal_missing"] = struct{}{}
			}
		case "request_body_chunk":
			if err := d.appendProxyChunk(ctx, projectID, attempt, true, metadata, digest, size, truncated); err != nil {
				return nil, nil, err
			}
		case "response_body_chunk":
			if err := d.appendProxyChunk(ctx, projectID, attempt, false, metadata, digest, size, truncated); err != nil {
				return nil, nil, err
			}
		case "request_body_finished":
			attempt.requestEnded++
			attempt.requestFinished = terminal == "complete"
			if !attempt.requestFinished {
				attempt.gaps["proxy_request_incomplete"] = struct{}{}
			}
		case "transport_attempt_finished":
			attempt.responseEnded++
			attempt.attemptTerminal = terminal
			attempt.attemptFinished = terminal == "complete" || (attempt.websocket && terminal != "")
			if !attempt.attemptFinished && !attempt.websocket {
				attempt.gaps["proxy_response_incomplete"] = struct{}{}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, attempt := range attempts {
		requiredEvents := []struct {
			count  int
			reason string
		}{
			{attempt.requestStarted, "proxy_request_start_not_unique"},
			{attempt.responseStarted, "proxy_response_start_not_unique"},
			{attempt.responseEnded, "proxy_attempt_finish_not_unique"},
		}
		if attempt.websocket {
			requiredEvents = append(requiredEvents,
				struct {
					count  int
					reason string
				}{attempt.websocketStarted, "proxy_websocket_start_not_unique"},
				struct {
					count  int
					reason string
				}{attempt.websocketEnded, "proxy_websocket_finish_not_unique"},
			)
			if attempt.websocketTerminal == "" || attempt.websocketTerminal != attempt.attemptTerminal {
				attempt.gaps["proxy_websocket_terminal_mismatch"] = struct{}{}
			}
		} else {
			requiredEvents = append(requiredEvents, struct {
				count  int
				reason string
			}{attempt.requestEnded, "proxy_request_finish_not_unique"})
		}
		for _, required := range requiredEvents {
			if required.count != 1 {
				attempt.gaps[required.reason] = struct{}{}
			}
		}
		for reason := range attempt.gaps {
			addProofGap(globalGaps, reason, 1)
		}
	}
	return attempts, globalGaps, nil
}

func proxyPath(value any) string {
	uri, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	path, _ := uri["path"].(string)
	if !boundedText(path, maxPathBytes) {
		return ""
	}
	return path
}

func (d *Deps) appendProxyChunk(ctx context.Context, projectID uuid.UUID, attempt *proxyAttempt, request bool, metadata map[string]any, digest []byte, size *int64, truncated bool) error {
	expected := &attempt.nextResponseChunk
	body := &attempt.response
	if request {
		expected = &attempt.nextRequestChunk
		body = &attempt.request
	}
	if jsonInteger(metadata["chunk_sequence"]) != *expected {
		attempt.gaps["proxy_body_sequence_gap"] = struct{}{}
	}
	*expected++
	if len(digest) != sha256.Size || size == nil || *size < 0 || *size > maxAuditBlobBytes || truncated {
		attempt.gaps["proxy_body_chunk_not_captured"] = struct{}{}
		return nil
	}
	bytes, err := d.readVerifiedBlob(ctx, projectID, digest, *size)
	if err != nil {
		if errors.Is(err, errSensitiveEvidenceUnavailable) {
			attempt.gaps["proxy_body_blob_unavailable"] = struct{}{}
			return nil
		}
		return fmt.Errorf("proxy body blob: %w", err)
	}
	if observed := jsonInteger(metadata["observed_size"]); observed != int64(len(bytes)) {
		attempt.gaps["proxy_body_size_mismatch"] = struct{}{}
		return nil
	}
	if err := body.appendBytes(bytes); err != nil {
		return fmt.Errorf("proxy body: %w", err)
	}
	return nil
}

func (d *Deps) appendProxyWebSocketFrame(ctx context.Context, projectID uuid.UUID, attempt *proxyAttempt, metadata map[string]any, digest []byte, size *int64, truncated bool) error {
	direction, _ := metadata["direction"].(string)
	body := &attempt.websocketResponse
	expected := &attempt.nextWSResponse
	messages := &attempt.wsResponseMessages
	switch direction {
	case "client_to_upstream":
		body, expected, messages = &attempt.websocketRequest, &attempt.nextWSRequest, &attempt.wsRequestMessages
	case "upstream_to_client":
	default:
		attempt.gaps["proxy_websocket_direction_invalid"] = struct{}{}
		return nil
	}
	*messages++
	if jsonInteger(metadata["message_sequence"]) != *expected {
		attempt.gaps["proxy_websocket_sequence_gap"] = struct{}{}
	}
	*expected++
	opcodeName, _ := metadata["opcode"].(string)
	opcode, ok := websocketOpcode(opcodeName)
	if !ok {
		attempt.gaps["proxy_websocket_opcode_invalid"] = struct{}{}
		return nil
	}
	observed, observedOK := jsonIntegerValue(metadata["observed_size"])
	var payload []byte
	switch {
	case observedOK && observed == 0 && len(digest) == 0 && size == nil && !truncated:
		payload = []byte{}
	case len(digest) == sha256.Size && size != nil && *size >= 0 && *size <= maxAuditBlobBytes && !truncated:
		value, err := d.readVerifiedBlob(ctx, projectID, digest, *size)
		if err != nil {
			if errors.Is(err, errSensitiveEvidenceUnavailable) {
				attempt.gaps["proxy_websocket_payload_unavailable"] = struct{}{}
				return nil
			}
			return fmt.Errorf("proxy WebSocket payload blob: %w", err)
		}
		payload = value
	default:
		attempt.gaps["proxy_websocket_payload_not_captured"] = struct{}{}
		return nil
	}
	if !observedOK || observed != int64(len(payload)) {
		attempt.gaps["proxy_websocket_payload_size_mismatch"] = struct{}{}
		return nil
	}
	expectedDigest, _ := metadata["sha256"].(string)
	actualDigest := sha256.Sum256(payload)
	if expectedDigest != "sha256:"+hex.EncodeToString(actualDigest[:]) {
		attempt.gaps["proxy_websocket_payload_digest_mismatch"] = struct{}{}
		return nil
	}
	if opcode == 8 {
		closeCode, closeCodeOK := jsonIntegerValue(metadata["close_code"])
		if closeCodeOK && closeCode > 0 && closeCode <= 65535 {
			wirePayload := make([]byte, 2, len(payload)+2)
			wirePayload[0], wirePayload[1] = byte(closeCode>>8), byte(closeCode)
			payload = append(wirePayload, payload...)
		} else if len(payload) > 0 {
			attempt.gaps["proxy_websocket_close_code_missing"] = struct{}{}
			return nil
		}
	}
	if err := body.appendMessage(opcode, payload); err != nil {
		return fmt.Errorf("proxy WebSocket payload: %w", err)
	}
	return nil
}

func websocketOpcode(value string) (byte, bool) {
	switch value {
	case "text":
		return 1, true
	case "binary":
		return 2, true
	case "close":
		return 8, true
	case "ping":
		return 9, true
	case "pong":
		return 10, true
	default:
		return 0, false
	}
}

type transportSignature struct {
	Method, Path, RequestSHA, ResponseSHA string
	Status                                uint16
	RequestBytes, ResponseBytes           int64
}

func compareTransportEvidence(attempts map[string]*proxyAttempt, streams []decodedStream) comparison {
	result := comparison{}
	proxyCounts := make(map[transportSignature]int64)
	nonModelCounts := make(map[transportSignature]int64)
	for _, attempt := range attempts {
		if attempt.modelTraffic == 1 {
			result.ProxyAttempts++
		} else if attempt.modelTraffic == 0 {
			result.UnknownClass++
		}
		if attempt.modelTraffic == 0 || !attempt.requestFinished || !attempt.attemptFinished || len(attempt.gaps) > 0 || !boundedText(attempt.method, maxMethodBytes) || !boundedText(attempt.path, maxPathBytes) || attempt.status == 0 {
			continue
		}
		signature := transportSignature{Method: attempt.method, Path: attempt.path, Status: attempt.status}
		request, response := attempt.request.finish(), attempt.response.finish()
		if attempt.websocket {
			request, response = attempt.websocketRequest.finish(), attempt.websocketResponse.finish()
		}
		signature.RequestBytes, signature.RequestSHA = request.Bytes, request.SHA256
		signature.ResponseBytes, signature.ResponseSHA = response.Bytes, response.SHA256
		if attempt.modelTraffic == 1 {
			proxyCounts[signature]++
			result.Eligible++
		} else {
			nonModelCounts[signature]++
		}
	}
	wireCounts := make(map[transportSignature]int64)
	for _, stream := range streams {
		if !stream.EligibleForDiff || stream.Method == "" || stream.Path == "" || stream.Status == 0 {
			continue
		}
		signature := transportSignature{Method: stream.Method, Path: stream.Path, Status: stream.Status, RequestBytes: stream.Request.Bytes, RequestSHA: stream.Request.SHA256, ResponseBytes: stream.Response.Bytes, ResponseSHA: stream.Response.SHA256}
		wireCounts[signature]++
	}
	for signature, count := range nonModelCounts {
		if wireCounts[signature] > count {
			wireCounts[signature] -= count
		} else {
			wireCounts[signature] = 0
		}
	}
	keys := make(map[transportSignature]struct{}, len(proxyCounts)+len(wireCounts))
	for signature := range proxyCounts {
		keys[signature] = struct{}{}
	}
	for signature := range wireCounts {
		keys[signature] = struct{}{}
	}
	for signature := range keys {
		proxy, wire := proxyCounts[signature], wireCounts[signature]
		result.Matched += min(proxy, wire)
		result.Missing += max(proxy-wire, 0)
		result.Extra += max(wire-proxy, 0)
		if proxy > 1 || wire > 1 {
			result.Ambiguous++
		}
	}
	return result
}

func boundedText(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

// TSharkDecoder is the production decoder. Construction fails unless the
// configured executable and every path ancestor are root-owned, canonical,
// non-symlinked, and not writable by group/other.
type TSharkDecoder struct {
	path     string
	identity DecoderIdentity
}

func NewTSharkDecoder(ctx context.Context, configuredPath string) (*TSharkDecoder, error) {
	path, err := filepath.Abs(configuredPath)
	if err != nil {
		return nil, err
	}
	if err := validateTrustedExecutable(path); err != nil {
		return nil, err
	}
	digest, err := digestFileBounded(path, maxTSharkBytes)
	if err != nil {
		return nil, err
	}
	privateHome, err := os.MkdirTemp("", "iorec-tshark-inspect-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(privateHome)
	versionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(versionCtx, path, "--version")
	command.Env = []string{"LC_ALL=C", "HOME=" + privateHome, "XDG_CONFIG_HOME=" + privateHome}
	command.Dir = privateHome
	stdout := &boundedWriter{limit: maxTSharkVersionBytes}
	stderr := &boundedWriter{limit: maxTSharkVersionBytes}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("trusted tshark version inspection failed: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("trusted tshark version output exceeded its limit")
	}
	first, _, _ := strings.Cut(string(stdout.bytes), "\n")
	const prefix = "TShark (Wireshark) "
	if !strings.HasPrefix(first, prefix) {
		return nil, fmt.Errorf("trusted tshark version output is unrecognized")
	}
	versionNumber := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(first, prefix)), ".")
	parts := strings.Split(versionNumber, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("trusted tshark version output is unrecognized")
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 4 || (major == 4 && minor < 4) {
		return nil, fmt.Errorf("tshark 4.4 or newer is required")
	}
	return &TSharkDecoder{
		path:     path,
		identity: DecoderIdentity{Kind: "tshark", Path: path, Version: first, SHA256: digest},
	}, nil
}

func (decoder *TSharkDecoder) Identity() DecoderIdentity { return decoder.identity }

func validateTrustedExecutable(path string) error {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return fmt.Errorf("tshark path is not canonical or contains a symlink")
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("tshark trust path is not root-owned and non-writable")
		}
		if current == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0o100 == 0) {
			return fmt.Errorf("tshark path is not an executable regular file")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

func digestFileBounded(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", fmt.Errorf("tshark executable exceeds its size limit")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type boundedWriter struct {
	limit    int64
	bytes    []byte
	exceeded bool
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	remaining := writer.limit - int64(len(writer.bytes))
	if remaining > 0 {
		retain := int64(len(value))
		if retain > remaining {
			retain = remaining
		}
		writer.bytes = append(writer.bytes, value[:retain]...)
	}
	if int64(len(value)) > remaining {
		writer.exceeded = true
	}
	return len(value), nil
}

func (decoder *TSharkDecoder) DecodeTransport(ctx context.Context, pcapPath, keysPath, privateHome string) (*transportDecodeResult, error) {
	preference := "tls.keylog_file:" + keysPath
	arguments := []string{"-n", "-2", "-r", pcapPath, "-o", preference, "-Y", "http || http2", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n", "-E", "escape=y", "--temp-dir", privateHome}
	for _, field := range tsharkFields {
		arguments = append(arguments, "-e", field)
	}
	command := exec.CommandContext(ctx, decoder.path, arguments...)
	command.Env = []string{"LC_ALL=C", "HOME=" + privateHome, "XDG_CONFIG_HOME=" + privateHome}
	command.Dir = privateHome
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	stderrResult := make(chan boundedDrainResult, 1)
	go func() { stderrResult <- drainBounded(stderr, maxTSharkStderrBytes) }()
	abort := func(cause error) (*transportDecodeResult, error) {
		_ = command.Process.Kill()
		_ = command.Wait()
		<-stderrResult
		return nil, cause
	}
	parser := newWireDecoder()
	reader := bufio.NewReaderSize(stdout, 64<<10)
	var stdoutBytes int64
	for {
		line, consumed, err := readBoundedLine(reader, maxTSharkLineBytes)
		stdoutBytes += int64(consumed)
		if stdoutBytes > maxTSharkStdoutBytes {
			return abort(fmt.Errorf("tshark stdout exceeded its byte limit"))
		}
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				if processErr := parser.processLine(line); processErr != nil {
					return abort(processErr)
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return abort(err)
		}
	}
	waitErr := command.Wait()
	stderrReport := <-stderrResult
	if stderrReport.err != nil {
		return nil, stderrReport.err
	}
	if waitErr != nil {
		return nil, fmt.Errorf("trusted tshark decoder exited unsuccessfully: %w", waitErr)
	}
	streams, gaps := parser.finish()
	websockets, websocketGaps, websocketStderr, err := decoder.decodeWebSockets(ctx, pcapPath, keysPath, privateHome)
	if err != nil {
		return nil, err
	}
	mergeProofGaps(gaps, websocketGaps)
	streams = mergeDecodedWebSockets(streams, websockets, gaps)
	stderrBytes := stderrReport.total
	if websocketStderr > math.MaxInt64-stderrBytes {
		stderrBytes = math.MaxInt64
	} else {
		stderrBytes += websocketStderr
	}
	return &transportDecodeResult{Rows: parser.rows, Streams: streams, Gaps: gaps, StderrBytes: stderrBytes}, nil
}

type websocketDirection struct {
	body              websocketBodyAccumulator
	fragmentedOpcode  byte
	fragmentedPayload []byte
	closed            bool
}

type websocketStreamBuilder struct {
	request, response websocketDirection
	gaps              map[string]struct{}
}

type decodedWebSocketStream struct {
	TCPStream       uint64
	Request         bodyDigest
	Response        bodyDigest
	EligibleForDiff bool
	Gaps            []string
}

type websocketWireDecoder struct {
	rows    int64
	streams map[uint64]*websocketStreamBuilder
	gaps    map[string]int64
}

func newWebSocketWireDecoder() *websocketWireDecoder {
	return &websocketWireDecoder{streams: make(map[uint64]*websocketStreamBuilder), gaps: make(map[string]int64)}
}

func (decoder *TSharkDecoder) decodeWebSockets(ctx context.Context, pcapPath, keysPath, privateHome string) ([]decodedWebSocketStream, map[string]int64, int64, error) {
	arguments := []string{
		"-n", "-2", "-r", pcapPath, "-o", "tls.keylog_file:" + keysPath,
		"-Y", "websocket", "-T", "ek", "-x", "-J", "tcp websocket", "--temp-dir", privateHome,
	}
	command := exec.CommandContext(ctx, decoder.path, arguments...)
	command.Env = []string{"LC_ALL=C", "HOME=" + privateHome, "XDG_CONFIG_HOME=" + privateHome}
	command.Dir = privateHome
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, 0, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, nil, 0, err
	}
	if err := command.Start(); err != nil {
		return nil, nil, 0, err
	}
	stderrResult := make(chan boundedDrainResult, 1)
	go func() { stderrResult <- drainBounded(stderr, maxTSharkStderrBytes) }()
	abort := func(cause error) ([]decodedWebSocketStream, map[string]int64, int64, error) {
		_ = command.Process.Kill()
		_ = command.Wait()
		<-stderrResult
		return nil, nil, 0, cause
	}
	parser := newWebSocketWireDecoder()
	reader := bufio.NewReaderSize(stdout, 64<<10)
	var stdoutBytes int64
	for {
		line, consumed, readErr := readBoundedLine(reader, maxTSharkEKLineBytes)
		stdoutBytes += int64(consumed)
		if stdoutBytes > maxTSharkStdoutBytes {
			return abort(fmt.Errorf("tshark WebSocket stdout exceeded its byte limit"))
		}
		if line != "" {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				if processErr := parser.processEKLine(line); processErr != nil {
					return abort(processErr)
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return abort(readErr)
		}
	}
	waitErr := command.Wait()
	stderrReport := <-stderrResult
	if stderrReport.err != nil {
		return nil, nil, 0, stderrReport.err
	}
	if waitErr != nil {
		return nil, nil, 0, fmt.Errorf("trusted tshark WebSocket decoder exited unsuccessfully: %w", waitErr)
	}
	streams, gaps := parser.finish()
	return streams, gaps, stderrReport.total, nil
}

func (decoder *websocketWireDecoder) processEKLine(line string) error {
	jsonDecoder := json.NewDecoder(strings.NewReader(line))
	jsonDecoder.UseNumber()
	var document map[string]any
	if err := jsonDecoder.Decode(&document); err != nil {
		return fmt.Errorf("tshark emitted invalid WebSocket EK JSON: %w", err)
	}
	layers, ok := document["layers"].(map[string]any)
	if !ok {
		if _, index := document["index"]; index {
			return nil
		}
		return fmt.Errorf("tshark WebSocket EK document has no layers")
	}
	tcp, err := ekSingleObject(layers["tcp"], "TCP")
	if err != nil {
		return err
	}
	tcpStream, err := ekUint(tcp["tcp_tcp_stream"], "TCP stream")
	if err != nil {
		return err
	}
	frames, err := ekObjects(layers["websocket"], "WebSocket")
	if err != nil || len(frames) == 0 {
		if err != nil {
			return err
		}
		return fmt.Errorf("tshark WebSocket EK layer is empty")
	}
	stream := decoder.streams[tcpStream]
	if stream == nil {
		if len(decoder.streams) == maxDecodedStreams {
			return fmt.Errorf("decoded WebSocket stream limit exceeded")
		}
		stream = &websocketStreamBuilder{gaps: make(map[string]struct{})}
		decoder.streams[tcpStream] = stream
	}
	for _, frame := range frames {
		decoder.rows++
		if decoder.rows > maxDecodedRows {
			return fmt.Errorf("decoded WebSocket frame-row limit exceeded")
		}
		fin, err := ekBool(frame["websocket_websocket_fin_raw"], "WebSocket FIN")
		if err != nil {
			return err
		}
		masked, err := ekBool(frame["websocket_websocket_mask_raw"], "WebSocket mask")
		if err != nil {
			return err
		}
		rsv, err := ekRawUint8(frame["websocket_websocket_rsv_raw"], "WebSocket RSV")
		if err != nil {
			return err
		}
		opcode, err := ekRawUint8(frame["websocket_websocket_opcode_raw"], "WebSocket opcode")
		if err != nil {
			return fmt.Errorf("tshark emitted an invalid WebSocket opcode")
		}
		payload, err := decodeWebSocketPayload(frame)
		if err != nil {
			return err
		}
		if rsv != 0 {
			stream.gaps["websocket_rsv_nonzero"] = struct{}{}
		}
		direction := &stream.response
		if masked {
			direction = &stream.request
		}
		if err := processWebSocketFrame(direction, opcode, fin, payload, stream.gaps); err != nil {
			return err
		}
	}
	return nil
}

func (decoder *websocketWireDecoder) finish() ([]decodedWebSocketStream, map[string]int64) {
	streams := make([]decodedWebSocketStream, 0, len(decoder.streams))
	for tcpStream, builder := range decoder.streams {
		if builder.request.fragmentedOpcode != 0 || builder.response.fragmentedOpcode != 0 {
			builder.gaps["websocket_fragment_end_missing"] = struct{}{}
		}
		gaps := make([]string, 0, len(builder.gaps))
		for gap := range builder.gaps {
			gaps = append(gaps, gap)
			addProofGap(decoder.gaps, gap, 1)
		}
		sort.Strings(gaps)
		streams = append(streams, decodedWebSocketStream{
			TCPStream: tcpStream, Request: builder.request.body.finish(), Response: builder.response.body.finish(),
			EligibleForDiff: len(gaps) == 0, Gaps: gaps,
		})
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].TCPStream < streams[j].TCPStream })
	return streams, decoder.gaps
}

func processWebSocketFrame(direction *websocketDirection, opcode byte, fin bool, payload []byte, gaps map[string]struct{}) error {
	if direction.closed {
		gaps["websocket_frame_after_close"] = struct{}{}
	}
	switch opcode {
	case 0:
		if direction.fragmentedOpcode == 0 {
			gaps["websocket_continuation_without_start"] = struct{}{}
			return nil
		}
		if err := appendWebSocketFragment(&direction.fragmentedPayload, payload); err != nil {
			return err
		}
		if fin {
			if err := direction.body.appendMessage(direction.fragmentedOpcode, direction.fragmentedPayload); err != nil {
				return err
			}
			direction.fragmentedOpcode = 0
			direction.fragmentedPayload = direction.fragmentedPayload[:0]
		}
	case 1, 2:
		if direction.fragmentedOpcode != 0 {
			direction.fragmentedOpcode = 0
			direction.fragmentedPayload = direction.fragmentedPayload[:0]
			gaps["websocket_new_data_before_fragment_end"] = struct{}{}
		}
		if fin {
			return direction.body.appendMessage(opcode, payload)
		}
		direction.fragmentedOpcode = opcode
		return appendWebSocketFragment(&direction.fragmentedPayload, payload)
	case 8, 9, 10:
		if !fin {
			gaps["websocket_control_frame_fragmented"] = struct{}{}
		}
		if len(payload) > 125 {
			gaps["websocket_control_frame_oversized"] = struct{}{}
		}
		if opcode == 8 {
			if len(payload) == 1 {
				gaps["websocket_close_payload_invalid"] = struct{}{}
			}
			direction.closed = true
		}
		return direction.body.appendMessage(opcode, payload)
	default:
		gaps["websocket_opcode_unsupported"] = struct{}{}
	}
	return nil
}

func appendWebSocketFragment(target *[]byte, payload []byte) error {
	if len(payload) > int(maxAuditBlobBytes)-len(*target) {
		return fmt.Errorf("WebSocket fragmented payload exceeded its limit")
	}
	*target = append(*target, payload...)
	return nil
}

func decodeWebSocketPayload(frame map[string]any) ([]byte, error) {
	indicator, err := ekRawUint8(frame["websocket_websocket_payload_length_raw"], "WebSocket payload-length byte")
	if err != nil {
		return nil, err
	}
	if indicator > 127 {
		return nil, fmt.Errorf("WebSocket payload-length byte is invalid")
	}
	declared := uint64(indicator)
	if indicator == 126 {
		extended, err := ekHexBytes(frame["websocket_websocket_payload_length_ext_16_raw"], "WebSocket 16-bit payload length", 2)
		if err != nil {
			return nil, err
		}
		declared = uint64(extended[0])<<8 | uint64(extended[1])
	} else if indicator == 127 {
		extended, err := ekHexBytes(frame["websocket_websocket_payload_length_ext_64_raw"], "WebSocket 64-bit payload length", 8)
		if err != nil {
			return nil, err
		}
		declared = 0
		for _, value := range extended {
			declared = declared<<8 | uint64(value)
		}
		if declared&(uint64(1)<<63) != 0 {
			return nil, fmt.Errorf("WebSocket payload length is invalid")
		}
	}
	if declared > uint64(maxAuditBlobBytes) {
		return nil, fmt.Errorf("WebSocket payload exceeded its audit limit")
	}
	payloadValue, present := frame["websocket_websocket_payload_raw"]
	if !present && declared == 0 {
		return []byte{}, nil
	}
	if !present {
		return nil, fmt.Errorf("tshark WebSocket frame has no decoded payload")
	}
	return ekHexBytes(payloadValue, "WebSocket payload", int(declared))
}

func ekSingleObject(value any, name string) (map[string]any, error) {
	if object, ok := value.(map[string]any); ok {
		return object, nil
	}
	if values, ok := value.([]any); ok && len(values) == 1 {
		if object, ok := values[0].(map[string]any); ok {
			return object, nil
		}
	}
	return nil, fmt.Errorf("tshark %s layer is ambiguous", name)
}

func ekObjects(value any, name string) ([]map[string]any, error) {
	if object, ok := value.(map[string]any); ok {
		return []map[string]any{object}, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("tshark %s layer is not an object or array", name)
	}
	objects := make([]map[string]any, 0, len(values))
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tshark %s layer is not an object", name)
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func ekUint(value any, name string) (uint64, error) {
	var text string
	switch value := value.(type) {
	case json.Number:
		text = value.String()
	case string:
		text = value
	default:
		return 0, fmt.Errorf("tshark emitted an invalid %s", name)
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tshark emitted an invalid %s", name)
	}
	return parsed, nil
}

func ekBool(value any, name string) (bool, error) {
	parsed, err := ekUint(value, name)
	if err != nil {
		return false, err
	}
	switch parsed {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("tshark emitted an invalid %s", name)
	}
}

func ekRawUint8(value any, name string) (byte, error) {
	text, ok := value.(string)
	if !ok || text == "" || len(text) > 2 {
		return 0, fmt.Errorf("tshark emitted an invalid %s", name)
	}
	parsed, err := strconv.ParseUint(text, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("tshark emitted an invalid %s", name)
	}
	return byte(parsed), nil
}

func ekHexBytes(value any, name string, length int) ([]byte, error) {
	text, ok := value.(string)
	if !ok || len(text) != length*2 {
		return nil, fmt.Errorf("tshark %s length is invalid", name)
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("tshark %s is invalid hexadecimal text", name)
	}
	return decoded, nil
}

func mergeDecodedWebSockets(streams []decodedStream, websockets []decodedWebSocketStream, gaps map[string]int64) []decodedStream {
	for _, websocket := range websockets {
		matches := make([]int, 0, 1)
		for index := range streams {
			if streams[index].Protocol == "http/1.1" && streams[index].TCPStream == websocket.TCPStream && streams[index].Status == 101 {
				matches = append(matches, index)
			}
		}
		if len(matches) != 1 {
			reason := "websocket_stream_without_unique_upgrade"
			if len(matches) > 1 {
				reason = "websocket_stream_upgrade_ambiguous"
			}
			addProofGap(gaps, reason, 1)
			continue
		}
		stream := &streams[matches[0]]
		stream.Protocol = "websocket"
		stream.Request, stream.Response = websocket.Request, websocket.Response
		stream.EligibleForDiff = stream.EligibleForDiff && websocket.EligibleForDiff
		stream.Gaps = append(stream.Gaps, websocket.Gaps...)
		sort.Strings(stream.Gaps)
	}
	return streams
}

type boundedDrainResult struct {
	total int64
	err   error
}

func drainBounded(reader io.Reader, retainedLimit int64) boundedDrainResult {
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		count, err := reader.Read(buffer)
		if int64(count) > math.MaxInt64-total {
			total = math.MaxInt64
		} else {
			total += int64(count)
		}
		if total > retainedLimit {
			// Continue draining so the child cannot block; only the count is kept.
		}
		if errors.Is(err, io.EOF) {
			return boundedDrainResult{total: total}
		}
		if err != nil {
			return boundedDrainResult{total: total, err: err}
		}
	}
}

func readBoundedLine(reader *bufio.Reader, limit int) (string, int, error) {
	var output strings.Builder
	total := 0
	for {
		fragment, err := reader.ReadString('\n')
		total += len(fragment)
		if total > limit {
			return "", total, fmt.Errorf("tshark output line exceeded its byte limit")
		}
		output.WriteString(fragment)
		if err != nil {
			return output.String(), total, err
		}
		if strings.HasSuffix(fragment, "\n") {
			return output.String(), total, nil
		}
	}
}

type streamBuilder struct {
	method, path string
	status       uint16
	bodies       map[string]*bodyAccumulator
	ended        map[string]bool
	tlsDecrypted bool
	gaps         map[string]struct{}
}

func newStreamBuilder() *streamBuilder {
	return &streamBuilder{bodies: make(map[string]*bodyAccumulator), ended: make(map[string]bool), gaps: make(map[string]struct{})}
}

func (stream *streamBuilder) body(endpoint string) *bodyAccumulator {
	body := stream.bodies[endpoint]
	if body == nil {
		body = &bodyAccumulator{}
		stream.bodies[endpoint] = body
	}
	return body
}

type h1Connection struct {
	client                      string
	requestCount, responseCount uint64
}

type wireDecoder struct {
	rows          int64
	h1Connections map[uint64]*h1Connection
	h1Streams     map[[2]uint64]*streamBuilder
	h2Clients     map[uint64]string
	h2Streams     map[[2]uint64]*streamBuilder
	gaps          map[string]int64
}

func newWireDecoder() *wireDecoder {
	return &wireDecoder{h1Connections: make(map[uint64]*h1Connection), h1Streams: make(map[[2]uint64]*streamBuilder), h2Clients: make(map[uint64]string), h2Streams: make(map[[2]uint64]*streamBuilder), gaps: make(map[string]int64)}
}

func (decoder *wireDecoder) h1Stream(key [2]uint64) *streamBuilder {
	stream := decoder.h1Streams[key]
	if stream == nil {
		stream = newStreamBuilder()
		decoder.h1Streams[key] = stream
	}
	return stream
}

func (decoder *wireDecoder) h2Stream(key [2]uint64) *streamBuilder {
	stream := decoder.h2Streams[key]
	if stream == nil {
		stream = newStreamBuilder()
		decoder.h2Streams[key] = stream
	}
	return stream
}

func (decoder *wireDecoder) processLine(line string) error {
	decoder.rows++
	if decoder.rows > maxDecodedRows {
		return fmt.Errorf("decoded packet-row limit exceeded")
	}
	columns := strings.Split(line, "\t")
	if len(columns) != tsharkColumnCount {
		return fmt.Errorf("tshark output column count changed")
	}
	if _, err := scalarUint(columns[0], "frame number", 64, true); err != nil {
		return err
	}
	tcpStream, err := scalarUint(columns[1], "TCP stream", 64, true)
	if err != nil {
		return err
	}
	source, err := parseEndpoint(columns[2], columns[3], columns[4])
	if err != nil {
		return err
	}
	destination, err := parseEndpoint(columns[5], columns[6], columns[7])
	if err != nil {
		return err
	}
	tlsDecrypted := columns[21] != ""
	if tlsDecrypted {
		if _, err := parseMultiUint(columns[21], "TLS content type", 8, 10); err != nil {
			return err
		}
	}
	if columns[12] != "" {
		if err := decoder.processH2(tcpStream, source, destination, columns[12:21], tlsDecrypted); err != nil {
			return err
		}
	} else if err := decoder.processH1(tcpStream, source, columns[8:12], tlsDecrypted); err != nil {
		return err
	}
	if len(decoder.h1Streams)+len(decoder.h2Streams) > maxDecodedStreams {
		return fmt.Errorf("decoded HTTP stream limit exceeded")
	}
	return nil
}

func (decoder *wireDecoder) processH1(tcpStream uint64, source string, columns []string, tlsDecrypted bool) error {
	method, err := scalarText(columns[0], "HTTP method", maxMethodBytes)
	if err != nil {
		return err
	}
	path := ""
	if columns[1] != "" {
		path, err = safePath(columns[1])
		if err != nil {
			return err
		}
	}
	statusValue, err := scalarUint(columns[2], "HTTP status", 16, false)
	if err != nil {
		return err
	}
	connection := decoder.h1Connections[tcpStream]
	if connection == nil {
		connection = &h1Connection{}
		decoder.h1Connections[tcpStream] = connection
	}
	var selected [2]uint64
	hasSelected := false
	if method != "" {
		connection.requestCount++
		if connection.client == "" {
			connection.client = source
		} else if connection.client != source {
			addProofGap(decoder.gaps, "http1_client_direction_conflict", 1)
		}
		selected, hasSelected = [2]uint64{tcpStream, connection.requestCount}, true
		stream := decoder.h1Stream(selected)
		setStreamText(&stream.method, method, stream.gaps, "method_conflict")
		if path != "" {
			setStreamText(&stream.path, path, stream.gaps, "target_conflict")
		}
		stream.ended[source] = true
		stream.tlsDecrypted = stream.tlsDecrypted || tlsDecrypted
	}
	if statusValue != 0 {
		connection.responseCount++
		selected, hasSelected = [2]uint64{tcpStream, connection.responseCount}, true
		stream := decoder.h1Stream(selected)
		setStreamStatus(&stream.status, uint16(statusValue), stream.gaps)
		stream.ended[source] = true
		stream.tlsDecrypted = stream.tlsDecrypted || tlsDecrypted
	}
	if columns[3] != "" {
		if !hasSelected && connection.client != "" {
			index := connection.responseCount
			if connection.client == source {
				index = connection.requestCount
			}
			if index > 0 {
				selected, hasSelected = [2]uint64{tcpStream, index}, true
			}
		}
		if !hasSelected {
			addProofGap(decoder.gaps, "http1_body_without_message", 1)
		} else {
			stream := decoder.h1Stream(selected)
			stream.tlsDecrypted = stream.tlsDecrypted || tlsDecrypted
			for _, value := range multi(columns[3]) {
				if _, err := stream.body(source).appendHex(value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (decoder *wireDecoder) processH2(tcpStream uint64, source, destination string, columns []string, tlsDecrypted bool) error {
	idsRaw, err := parseMultiUint(columns[0], "HTTP/2 stream ID", 32, 10)
	if err != nil {
		return err
	}
	typesRaw, err := parseMultiUint(columns[1], "HTTP/2 frame type", 8, 10)
	if err != nil {
		return err
	}
	lengths, err := parseMultiUint(columns[2], "HTTP/2 frame length", 64, 10)
	if err != nil {
		return err
	}
	flags, err := parseMultiUint(columns[3], "HTTP/2 flags", 8, 16)
	if err != nil {
		return err
	}
	if len(idsRaw) != len(typesRaw) || len(idsRaw) != len(lengths) || len(idsRaw) != len(flags) {
		return fmt.Errorf("HTTP/2 frame fields lost occurrence alignment")
	}
	headerPositions := make([]int, 0)
	for index := range idsRaw {
		if idsRaw[index] > 0 && typesRaw[index] == 1 {
			headerPositions = append(headerPositions, index)
		}
	}
	methods, paths, statuses := multi(columns[4]), multi(columns[5]), multi(columns[6])
	if len(methods) > 0 {
		if len(methods) != len(headerPositions) || len(paths) != len(methods) {
			addProofGap(decoder.gaps, "http2_request_headers_ambiguous", 1)
		} else {
			if existing := decoder.h2Clients[tcpStream]; existing == "" {
				decoder.h2Clients[tcpStream] = source
			} else if existing != source {
				addProofGap(decoder.gaps, "http2_client_direction_conflict", 1)
			}
			for position, index := range headerPositions {
				method, err := checkedText(methods[position], "HTTP/2 method", maxMethodBytes)
				if err != nil {
					return err
				}
				path, err := safePath(paths[position])
				if err != nil {
					return err
				}
				stream := decoder.h2Stream([2]uint64{tcpStream, idsRaw[index]})
				setStreamText(&stream.method, method, stream.gaps, "method_conflict")
				setStreamText(&stream.path, path, stream.gaps, "target_conflict")
			}
		}
	}
	if len(statuses) > 0 {
		if len(statuses) != len(headerPositions) {
			addProofGap(decoder.gaps, "http2_response_headers_ambiguous", 1)
		} else {
			if existing := decoder.h2Clients[tcpStream]; existing == "" {
				decoder.h2Clients[tcpStream] = destination
			} else if existing != destination {
				addProofGap(decoder.gaps, "http2_server_direction_conflict", 1)
			}
			for position, index := range headerPositions {
				status, err := strconv.ParseUint(statuses[position], 10, 16)
				if err != nil || status == 0 {
					return fmt.Errorf("tshark emitted an invalid HTTP/2 status")
				}
				stream := decoder.h2Stream([2]uint64{tcpStream, idsRaw[index]})
				setStreamStatus(&stream.status, uint16(status), stream.gaps)
			}
		}
	}
	dataPositions := make([]int, 0)
	paddingPositions := make([]int, 0)
	for index := range idsRaw {
		if typesRaw[index] == 0 && idsRaw[index] > 0 {
			dataPositions = append(dataPositions, index)
		}
		if typesRaw[index] == 0 || typesRaw[index] == 1 || typesRaw[index] == 5 {
			paddingPositions = append(paddingPositions, index)
		}
	}
	padding, err := parseMultiUint(columns[8], "HTTP/2 pad length", 64, 10)
	if err != nil {
		return err
	}
	paddingByPosition := make(map[int]uint64)
	if len(padding) != len(paddingPositions) {
		addProofGap(decoder.gaps, "http2_padding_occurrence_alignment_failed", 1)
	} else {
		for index, position := range paddingPositions {
			paddingByPosition[position] = padding[index]
			if flags[position]&0x8 == 0 && padding[index] != 0 {
				addProofGap(decoder.gaps, "http2_unpadded_frame_has_pad_length", 1)
			}
		}
	}
	bodyLengths := make(map[int]uint64)
	bodyPositions := make([]int, 0)
	for _, position := range dataPositions {
		overhead := uint64(0)
		if flags[position]&0x8 != 0 {
			padding, ok := paddingByPosition[position]
			if !ok {
				padding = lengths[position]
			}
			overhead = padding + 1
		}
		if lengths[position] > overhead {
			bodyLengths[position] = lengths[position] - overhead
			bodyPositions = append(bodyPositions, position)
		} else {
			bodyLengths[position] = 0
		}
	}
	data := multi(columns[7])
	alignedAll, alignedBody := len(data) == len(dataPositions), len(data) == len(bodyPositions)
	if len(dataPositions) > 0 && !alignedAll && !alignedBody {
		addProofGap(decoder.gaps, "http2_data_occurrence_alignment_failed", 1)
	} else {
		allIndex, bodyIndex := 0, 0
		for _, position := range dataPositions {
			value := ""
			if alignedAll {
				value = data[allIndex]
				allIndex++
			} else if bodyLengths[position] > 0 {
				value = data[bodyIndex]
				bodyIndex++
			}
			if bodyLengths[position] > 0 {
				stream := decoder.h2Stream([2]uint64{tcpStream, idsRaw[position]})
				decoded, err := stream.body(source).appendHex(value)
				if err != nil {
					return err
				}
				if uint64(decoded) != bodyLengths[position] {
					stream.gaps["data_length_mismatch"] = struct{}{}
					addProofGap(decoder.gaps, "http2_data_length_mismatch", 1)
				}
			}
		}
	}
	for index, id := range idsRaw {
		if id == 0 {
			continue
		}
		stream := decoder.h2Stream([2]uint64{tcpStream, id})
		stream.tlsDecrypted = stream.tlsDecrypted || tlsDecrypted
		if flags[index]&0x1 != 0 {
			stream.ended[source] = true
		}
	}
	return nil
}

func (decoder *wireDecoder) finish() ([]decodedStream, map[string]int64) {
	streams := make([]decodedStream, 0, len(decoder.h1Streams)+len(decoder.h2Streams))
	for key, builder := range decoder.h1Streams {
		client := ""
		if connection := decoder.h1Connections[key[0]]; connection != nil {
			client = connection.client
		}
		stream := finishDecodedStream("http/1.1", key[0], 0, client, builder, false)
		for _, gap := range stream.Gaps {
			addProofGap(decoder.gaps, gap, 1)
		}
		streams = append(streams, stream)
	}
	for key, builder := range decoder.h2Streams {
		stream := finishDecodedStream("http/2", key[0], uint32(key[1]), decoder.h2Clients[key[0]], builder, true)
		for _, gap := range stream.Gaps {
			addProofGap(decoder.gaps, gap, 1)
		}
		streams = append(streams, stream)
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].TCPStream != streams[j].TCPStream {
			return streams[i].TCPStream < streams[j].TCPStream
		}
		return streams[i].HTTP2StreamID < streams[j].HTTP2StreamID
	})
	return streams, decoder.gaps
}

func finishDecodedStream(protocol string, tcpStream uint64, h2ID uint32, client string, builder *streamBuilder, requireEnd bool) decodedStream {
	gaps := make(map[string]struct{}, len(builder.gaps)+4)
	for gap := range builder.gaps {
		gaps[gap] = struct{}{}
	}
	request, response := bodyDigest{}, bodyDigest{}
	requestEnd, responseEnd := false, false
	if client == "" {
		gaps["stream_client_direction_unknown"] = struct{}{}
	} else {
		if body := builder.bodies[client]; body != nil {
			request = body.finish()
		} else {
			request = (&bodyAccumulator{}).finish()
		}
		requestEnd = builder.ended[client]
		servers := make(map[string]struct{})
		for endpoint := range builder.bodies {
			if endpoint != client {
				servers[endpoint] = struct{}{}
			}
		}
		for endpoint := range builder.ended {
			if endpoint != client {
				servers[endpoint] = struct{}{}
			}
		}
		serverNames := make([]string, 0, len(servers))
		for endpoint := range servers {
			serverNames = append(serverNames, endpoint)
		}
		sort.Strings(serverNames)
		if len(serverNames) > 1 {
			gaps["stream_has_multiple_server_endpoints"] = struct{}{}
		}
		if len(serverNames) > 0 {
			server := serverNames[0]
			if body := builder.bodies[server]; body != nil {
				response = body.finish()
			} else {
				response = (&bodyAccumulator{}).finish()
			}
			responseEnd = builder.ended[server]
		}
	}
	if request.SHA256 == "" {
		request = (&bodyAccumulator{}).finish()
	}
	if response.SHA256 == "" {
		response = (&bodyAccumulator{}).finish()
	}
	if builder.method == "" {
		gaps["stream_method_missing"] = struct{}{}
	}
	if builder.path == "" {
		gaps["stream_target_missing"] = struct{}{}
	}
	if builder.status == 0 {
		gaps["stream_status_missing"] = struct{}{}
	}
	if requireEnd && !requestEnd {
		gaps["http2_request_end_missing"] = struct{}{}
	}
	if requireEnd && !responseEnd {
		gaps["http2_response_end_missing"] = struct{}{}
	}
	gapList := make([]string, 0, len(gaps))
	for gap := range gaps {
		gapList = append(gapList, gap)
	}
	sort.Strings(gapList)
	return decodedStream{Protocol: protocol, TCPStream: tcpStream, HTTP2StreamID: h2ID, Method: builder.method, Path: builder.path, Status: builder.status, Request: request, Response: response, TLSDecrypted: builder.tlsDecrypted, EligibleForDiff: len(gapList) == 0, Gaps: gapList}
}

func setStreamText(slot *string, value string, gaps map[string]struct{}, conflict string) {
	if *slot != "" && *slot != value {
		gaps[conflict] = struct{}{}
	} else if *slot == "" {
		*slot = value
	}
}

func setStreamStatus(slot *uint16, value uint16, gaps map[string]struct{}) {
	if *slot != 0 && *slot != value {
		gaps["status_conflict"] = struct{}{}
	} else if *slot == 0 {
		*slot = value
	}
}

func multi(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, "|")
}

func scalarUint(value, name string, bits int, required bool) (uint64, error) {
	if value == "" {
		if required {
			return 0, fmt.Errorf("tshark row has no %s", name)
		}
		return 0, nil
	}
	if strings.Contains(value, "|") {
		return 0, fmt.Errorf("tshark emitted multiple %s values", name)
	}
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("tshark emitted an invalid %s", name)
	}
	return parsed, nil
}

func parseMultiUint(value, name string, bits, base int) ([]uint64, error) {
	items := multi(value)
	result := make([]uint64, 0, len(items))
	for _, item := range items {
		item = strings.TrimPrefix(item, "0x")
		parsed, err := strconv.ParseUint(item, base, bits)
		if err != nil {
			return nil, fmt.Errorf("tshark emitted an invalid %s", name)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func scalarText(value, name string, limit int) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "|") {
		return "", fmt.Errorf("tshark emitted multiple %s values", name)
	}
	return checkedText(value, name, limit)
}

func checkedText(value, name string, limit int) (string, error) {
	if !boundedText(value, limit) {
		return "", fmt.Errorf("tshark %s is empty, oversized, or control-bearing", name)
	}
	return value, nil
}

func safePath(target string) (string, error) {
	if len(target) > maxPathBytes {
		return "", fmt.Errorf("decoded request target exceeds its limit")
	}
	path, _, _ := strings.Cut(target, "?")
	return checkedText(path, "request path", maxPathBytes)
}

func parseEndpoint(ipv4, ipv6, port string) (string, error) {
	address := ipv4
	if address == "" {
		address = ipv6
	}
	parsedIP := net.ParseIP(address)
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if parsedIP == nil || err != nil || parsedPort == 0 {
		return "", fmt.Errorf("tshark row has an invalid IP endpoint")
	}
	return net.JoinHostPort(parsedIP.String(), strconv.Itoa(int(parsedPort))), nil
}
