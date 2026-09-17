package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
)

func tsharkTestRow(columns [tsharkColumnCount]string) string {
	return strings.Join(columns[:], "\t")
}

func digestForTest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func hasGap(gaps []string, want string) bool {
	for _, gap := range gaps {
		if gap == want {
			return true
		}
	}
	return false
}

func TestWireDecoderReconstructsHTTP2RequestAndResponse(t *testing.T) {
	request := [tsharkColumnCount]string{
		"4", "0", "127.0.0.1", "", "50000", "127.0.0.1", "", "8443",
		"", "", "", "", "0|0|1|1", "4|8|1|0", "18|4|20|5", "0x00|0x00|0x04|0x01",
		"POST", "/v1/responses?api_key=secret", "", "68656c6c6f", "0|0", "23",
	}
	response := [tsharkColumnCount]string{
		"8", "0", "127.0.0.1", "", "8443", "127.0.0.1", "", "50000",
		"", "", "", "", "1|1|1|1", "1|0|0|0", "10|3|2|0", "0x04|0x00|0x00|0x01",
		"", "", "200", "776f72|6c64|776f726c64", "0|0|0|0", "23",
	}
	decoder := newWireDecoder()
	if err := decoder.processLine(tsharkTestRow(request)); err != nil {
		t.Fatal(err)
	}
	if err := decoder.processLine(tsharkTestRow(response)); err != nil {
		t.Fatal(err)
	}
	streams, gaps := decoder.finish()
	if len(gaps) != 0 {
		t.Fatalf("unexpected reconstruction gaps: %+v", gaps)
	}
	if len(streams) != 1 {
		t.Fatalf("expected one stream, got %d", len(streams))
	}
	stream := streams[0]
	if stream.Protocol != "http/2" || stream.HTTP2StreamID != 1 || stream.Method != "POST" || stream.Path != "/v1/responses" || stream.Status != 200 {
		t.Fatalf("wrong reconstructed stream: %+v", stream)
	}
	if stream.Request.Bytes != 5 || stream.Request.SHA256 != digestForTest("hello") || stream.Response.Bytes != 5 || stream.Response.SHA256 != digestForTest("world") {
		t.Fatalf("wrong reconstructed bodies: request=%+v response=%+v", stream.Request, stream.Response)
	}
	if !stream.TLSDecrypted || !stream.EligibleForDiff {
		t.Fatalf("complete decrypted stream was not eligible: %+v", stream)
	}
}

func TestWireDecoderRejectsAmbiguousHTTP2OccurrenceAlignment(t *testing.T) {
	row := [tsharkColumnCount]string{
		"1", "0", "127.0.0.1", "", "50000", "127.0.0.1", "", "8443",
		"", "", "", "", "1|3", "1|1", "10|10", "0x04|0x04",
		"POST", "/one", "", "", "0|0", "",
	}
	decoder := newWireDecoder()
	if err := decoder.processLine(tsharkTestRow(row)); err != nil {
		t.Fatal(err)
	}
	streams, gaps := decoder.finish()
	if gaps["http2_request_headers_ambiguous"] != 1 {
		t.Fatalf("ambiguous occurrence alignment was not reported: %+v", gaps)
	}
	for _, stream := range streams {
		if stream.EligibleForDiff || !hasGap(stream.Gaps, "http2_request_end_missing") {
			t.Fatalf("ambiguous stream was eligible or missed end gap: %+v", stream)
		}
	}
}

func TestWireDecoderValidatesHTTP2PaddingLength(t *testing.T) {
	padded := [tsharkColumnCount]string{
		"1", "0", "127.0.0.1", "", "50000", "127.0.0.1", "", "8443",
		"", "", "", "", "1|1", "1|0", "20|8", "0x04|0x09",
		"POST", "/padded", "", "68656c6c6f", "0|2", "",
	}
	decoder := newWireDecoder()
	if err := decoder.processLine(tsharkTestRow(padded)); err != nil {
		t.Fatal(err)
	}
	streams, gaps := decoder.finish()
	if gaps["http2_data_length_mismatch"] != 0 || streams[0].Request.Bytes != 5 || streams[0].Request.SHA256 != digestForTest("hello") {
		t.Fatalf("padding was included in body length/hash: streams=%+v gaps=%+v", streams, gaps)
	}

	padded[19] = "68656c6c"
	decoder = newWireDecoder()
	if err := decoder.processLine(tsharkTestRow(padded)); err != nil {
		t.Fatal(err)
	}
	streams, gaps = decoder.finish()
	if gaps["http2_data_length_mismatch"] != 1 || !hasGap(streams[0].Gaps, "data_length_mismatch") {
		t.Fatalf("short padded body did not fail closed: streams=%+v gaps=%+v", streams, gaps)
	}
}

func TestWireDecoderReconstructsHTTP1AndComparesExactBodies(t *testing.T) {
	request := [tsharkColumnCount]string{
		"4", "0", "127.0.0.1", "", "50000", "127.0.0.1", "", "8080",
		"POST", "/v1/chat?token=secret", "", "6869",
	}
	response := [tsharkColumnCount]string{
		"8", "0", "127.0.0.1", "", "8080", "127.0.0.1", "", "50000",
		"", "/v1/chat?token=secret", "200", "6f6b",
	}
	decoder := newWireDecoder()
	if err := decoder.processLine(tsharkTestRow(request)); err != nil {
		t.Fatal(err)
	}
	if err := decoder.processLine(tsharkTestRow(response)); err != nil {
		t.Fatal(err)
	}
	streams, gaps := decoder.finish()
	if len(gaps) != 0 || len(streams) != 1 || !streams[0].EligibleForDiff {
		t.Fatalf("HTTP/1 reconstruction incomplete: streams=%+v gaps=%+v", streams, gaps)
	}
	attempt := newProxyAttempt()
	attempt.method, attempt.path, attempt.status = "POST", "/v1/chat", 200
	attempt.modelTraffic, attempt.requestFinished, attempt.attemptFinished = 1, true, true
	if err := attempt.request.appendBytes([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := attempt.response.appendBytes([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	comparison := compareTransportEvidence(map[string]*proxyAttempt{"attempt": attempt}, streams)
	if comparison.ProxyAttempts != 1 || comparison.Eligible != 1 || comparison.Matched != 1 || comparison.Missing != 0 || comparison.Extra != 0 {
		t.Fatalf("exact comparison failed: %+v", comparison)
	}
}

func TestTSharkDecoderReconstructsRealCapture(t *testing.T) {
	tsharkPath := os.Getenv("TEST_TSHARK_PATH")
	pcapPath := os.Getenv("TEST_TSHARK_PCAP")
	keysPath := os.Getenv("TEST_TSHARK_KEYS")
	wantText := os.Getenv("TEST_TSHARK_EXPECT_STREAMS")
	if tsharkPath == "" || pcapPath == "" || keysPath == "" || wantText == "" {
		t.Skip("real TShark fixture environment is not configured")
	}
	want, err := strconv.Atoi(wantText)
	if err != nil || want < 1 {
		t.Fatalf("invalid TEST_TSHARK_EXPECT_STREAMS %q", wantText)
	}
	decoder, err := NewTSharkDecoder(context.Background(), tsharkPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := decoder.DecodeTransport(context.Background(), pcapPath, keysPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Streams) != want || len(result.Gaps) != 0 || result.StderrBytes != 0 {
		t.Fatalf("real capture did not reconstruct cleanly: rows=%d streams=%+v gaps=%+v stderr=%d", result.Rows, result.Streams, result.Gaps, result.StderrBytes)
	}
	for _, stream := range result.Streams {
		if !stream.EligibleForDiff || stream.Request.SHA256 == "" || stream.Response.SHA256 == "" {
			t.Fatalf("real capture produced an ineligible stream: %+v", stream)
		}
	}
}

func completeBoundaryEvents(policy string, downstreamTLS *bool) []rawEvent {
	configured, _ := json.Marshal(map[string]any{
		"policy_mode": policy, "default_egress_policy": "drop", "dns_enabled": false, "ipv6_enabled": false,
	})
	pcapStart, _ := json.Marshal(map[string]any{"scope": "task_egress", "egress_policy": policy})
	confined, _ := json.Marshal(map[string]any{"capabilities_zero": true, "bounding_capabilities_zero": true, "no_new_privileges": true})
	networkFinished, _ := json.Marshal(map[string]any{
		"policy_mode": policy, "hosts_snapshot_verified_at_start": true,
		"firewall_verified_at_target_start": true, "firewall_verified_at_target_end": true,
		"firewall_verified_at_stop": true, "ipv6_disabled_at_start": true, "ipv6_disabled_at_stop": true,
		"helper_exited_before_stop": false, "helper_exit_success": true, "helper_termination_signal": nil,
		"helper_forced_kill": false, "helper_stdout_omitted": 0, "helper_stderr_omitted": 0,
		"post_target_firewall": map[string]any{"loopback_packets": 0, "proxy_packets": 0, "transparent_packets": 0, "denied_packets": 0},
	})
	pcapFinished, _ := json.Marshal(map[string]any{
		"limit_reached": false, "packets_dropped": 0, "packets_missed": 0,
		"exit_success": true, "forced_kill": false, "stderr_bytes_omitted": 0,
	})
	events := []rawEvent{
		{Event: "task_network_isolation_configured", Payload: configured},
		{Event: "pcap_capture_started", Payload: pcapStart},
		{Event: "task_network_target_confined", Payload: confined, TerminalState: "complete"},
		{Event: "task_network_target_window_closed", Payload: json.RawMessage(`{}`), TerminalState: "complete"},
		{Event: "task_network_isolation_finished", Payload: networkFinished, TerminalState: "complete"},
		{Event: "pcap_capture_finished", Payload: pcapFinished, TerminalState: "complete"},
	}
	if downstreamTLS != nil {
		payload, _ := json.Marshal(map[string]any{"downstream_tls": *downstreamTLS})
		events = append(events, rawEvent{Event: "transparent_interception_prepared", Payload: payload})
	}
	return events
}

func TestSourceBoundaryRequiresExplicitCompleteReportFields(t *testing.T) {
	valid := completeBoundaryEvents("proxy_only", nil)
	boundary := verifySourceBoundaryEvents(valid)
	if !boundary.OK || !boundary.Cleartext || len(boundary.Gaps) != 0 {
		t.Fatalf("complete proxy-only boundary was rejected: %+v", boundary)
	}

	var payload map[string]any
	if err := json.Unmarshal(valid[5].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, "packets_missed")
	valid[5].Payload, _ = json.Marshal(payload)
	boundary = verifySourceBoundaryEvents(valid)
	if boundary.OK || boundary.Gaps["packet_capture_not_complete"] != 1 {
		t.Fatalf("missing zero-valued report field did not fail closed: %+v", boundary)
	}

	valid = completeBoundaryEvents("proxy_only", nil)
	if err := json.Unmarshal(valid[5].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	payload["packets_missed"] = 0.5
	valid[5].Payload, _ = json.Marshal(payload)
	boundary = verifySourceBoundaryEvents(valid)
	if boundary.OK || boundary.Gaps["packet_capture_not_complete"] != 1 {
		t.Fatalf("fractional counter did not fail closed: %+v", boundary)
	}
}

func TestSourceBoundaryRequiresTransparentInterceptionEvidence(t *testing.T) {
	missing := verifySourceBoundaryEvents(completeBoundaryEvents("transparent", nil))
	if missing.OK || missing.Cleartext || missing.Gaps["transparent_interception_evidence_not_unique"] != 1 {
		t.Fatalf("missing transparent evidence was accepted: %+v", missing)
	}
	downstreamTLS := false
	complete := verifySourceBoundaryEvents(completeBoundaryEvents("transparent", &downstreamTLS))
	if !complete.OK || !complete.Cleartext || complete.TransparentTLS || len(complete.Gaps) != 0 {
		t.Fatalf("complete transparent-cleartext evidence was rejected: %+v", complete)
	}
	downstreamTLS = true
	complete = verifySourceBoundaryEvents(completeBoundaryEvents("transparent", &downstreamTLS))
	if !complete.OK || complete.Cleartext || !complete.TransparentTLS || len(complete.Gaps) != 0 {
		t.Fatalf("complete transparent-TLS evidence was rejected: %+v", complete)
	}
}

func TestVerifiedTransportProofValidationFailsClosed(t *testing.T) {
	identity := DecoderIdentity{Kind: "tshark", Path: "/usr/bin/tshark", Version: "TShark (Wireshark) 4.4.18", SHA256: strings.Repeat("a", 64)}
	valid := PlatformTransportProof{
		SchemaVersion: platformProofSchema, Status: "verified", Verified: true,
		CompletenessBoundary: platformProofBoundary, ProcessorVersion: TransportAuditVersion,
		GeneratedAt: time.Now().UTC(), Decoder: &identity, SourceBoundaryOK: true,
		PcapRecords: 1, PcapBytes: 24, DecodedRows: 2, DecodedStreams: 1,
		ProxyAttempts: 1, ProxyAttemptsEligible: 1, MatchedAttempts: 1,
		PayloadDiffPassed: true, Gaps: []ProofGap{},
	}
	if !validTransportProof(valid) {
		t.Fatal("internally consistent verified proof was rejected")
	}
	cases := map[string]func(*PlatformTransportProof){
		"decoder missing":      func(proof *PlatformTransportProof) { proof.Decoder = nil },
		"negative count":       func(proof *PlatformTransportProof) { proof.ExtraOnWire = -1 },
		"matched mismatch":     func(proof *PlatformTransportProof) { proof.MatchedAttempts = 0 },
		"payload diff missing": func(proof *PlatformTransportProof) { proof.PayloadDiffPassed = false },
		"pcap missing":         func(proof *PlatformTransportProof) { proof.PcapBytes = 0 },
		"bad decoder digest":   func(proof *PlatformTransportProof) { proof.Decoder.SHA256 = "not-a-digest" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			decoder := identity
			candidate.Decoder = &decoder
			mutate(&candidate)
			if validTransportProof(candidate) {
				t.Fatalf("inconsistent proof was accepted: %+v", candidate)
			}
		})
	}
	incomplete := valid
	incomplete.Status, incomplete.Verified = "incomplete", false
	incomplete.Gaps = []ProofGap{{Reason: "z_gap", Occurrences: 1}, {Reason: "a_gap", Occurrences: 1}}
	if validTransportProof(incomplete) {
		t.Fatal("unsorted proof gaps were accepted")
	}
}

type auditObjectStore struct {
	objects map[string][]byte
}

func (store *auditObjectStore) Put(_ context.Context, key string, reader io.Reader, size int64, _ string) error {
	value, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return err
	}
	if int64(len(value)) != size {
		return errors.New("test object size mismatch")
	}
	store.objects[key] = append([]byte(nil), value...)
	return nil
}

func (store *auditObjectStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	value, ok := store.objects[key]
	if !ok {
		return nil, objstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

func (store *auditObjectStore) Stat(_ context.Context, key string) (int64, error) {
	value, ok := store.objects[key]
	if !ok {
		return 0, objstore.ErrNotFound
	}
	return int64(len(value)), nil
}

func (store *auditObjectStore) Delete(_ context.Context, key string) error {
	delete(store.objects, key)
	return nil
}

type stubTransportDecoder struct {
	expectedPcap []byte
	expectedKeys []byte
	result       *transportDecodeResult
}

func (decoder *stubTransportDecoder) Identity() DecoderIdentity {
	return DecoderIdentity{Kind: "test", Path: "/test/tshark", Version: "TShark (Wireshark) 4.4.18", SHA256: strings.Repeat("a", 64)}
}

func (decoder *stubTransportDecoder) DecodeTransport(_ context.Context, pcapPath, keysPath, _ string) (*transportDecodeResult, error) {
	pcap, err := os.ReadFile(pcapPath)
	if err != nil {
		return nil, err
	}
	keys, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pcap, decoder.expectedPcap) || !bytes.Equal(keys, decoder.expectedKeys) {
		return nil, fmt.Errorf("materialized artifacts differ: pcap=%x keys=%x", pcap, keys)
	}
	return decoder.result, nil
}

func TestTransportAuditPersistsVerifiedProofAndCoverageConsumesIt(t *testing.T) {
	db := pipelineTestDB(t)
	ctx := context.Background()
	tenant, project := uuid.New(), uuid.New()
	run := "run-transport-audit-" + uuid.NewString()[:8]
	recording := run + "#0000"
	if _, err := db.Pool.Exec(ctx, `insert into tenants(id,name) values($1,$2)`, tenant, "t-"+tenant.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'p')`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into capture_runs(id,project_id) values($1,$2)`, run, project); err != nil {
		t.Fatal(err)
	}
	manifest := `{"probe_plan":{},"coverage":{"claim":"best-effort","unknown_tls_surfaces":0,"unparsed_connections":0,"unknown_egress":0,"model_bypass_connections":0,"capture_drops":0}}`
	if _, err := db.Pool.Exec(ctx, `insert into recordings(id,project_id,capture_run_id,state,manifest) values($1,$2,$3,'sealed',$4::jsonb)`, recording, project, run, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_inferences(id,native_id,recording_id,capture_run_id,project_id,status,processor_version) values($1,'inference-1',$2,$3,$4,'observed','test')`, InferenceKey(run, "inference-1"), recording, run, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `insert into model_attempts(id,native_id,recording_id,project_id,capture_run_id,inference_id,source,api_mode,terminal_state,processor_version) values($1,'attempt-1',$2,$3,$4,$5,'proxy','responses','completed','test')`, AttemptKey(run, "attempt-1"), recording, project, run, InferenceKey(run, "inference-1")); err != nil {
		t.Fatal(err)
	}

	objects := &auditObjectStore{objects: make(map[string][]byte)}
	addBlob := func(key, mediaType string, value []byte) []byte {
		digest := sha256.Sum256(value)
		objects.objects[key] = append([]byte(nil), value...)
		if _, err := db.Pool.Exec(ctx, `insert into blobs(project_id,sha256,size,media_type,object_key) values($1,$2,$3,$4,$5)`, project, digest[:], len(value), mediaType, key); err != nil {
			t.Fatal(err)
		}
		return digest[:]
	}
	pcapBytes, requestBytes, responseBytes := []byte("bounded-pcap-fixture"), []byte("hi"), []byte("ok")
	pcapDigest := addBlob("audit/pcap", pcapMediaType, pcapBytes)
	requestDigest := addBlob("audit/request", "application/octet-stream", requestBytes)
	responseDigest := addBlob("audit/response", "application/octet-stream", responseBytes)

	seq := int64(0)
	insertEvent := func(source, event, attemptID string, payload any, digest []byte, size *int64, mediaType, terminal string) {
		seq++
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool.Exec(ctx, `insert into recording_events
			(recording_id,seq,monotonic_ns,wall_time,source,event,attempt_id,payload,payload_sha256,payload_size,raw_media_type,raw_truncated,batch_id,terminal_state)
			values($1,$2,$2,$3,$4,$5,nullif($6,''),$7::jsonb,$8,$9,nullif($10,''),false,$11,nullif($12,''))`,
			recording, seq, time.Now().UTC().Add(time.Duration(seq)*time.Millisecond), source, event, attemptID, string(encoded), digest, size, mediaType, fmt.Sprintf("batch-%d", seq), terminal); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range completeBoundaryEvents("proxy_only", nil) {
		var payload any
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		insertEvent("runner", event.Event, "", payload, nil, nil, "", event.TerminalState)
	}
	pcapSize := int64(len(pcapBytes))
	insertEvent("pcap", "pcap_capture_chunk", "", map[string]any{"chunk_sequence": 1, "offset": 0, "bytes": pcapSize}, pcapDigest, &pcapSize, pcapMediaType, "")
	requestSize, responseSize := int64(len(requestBytes)), int64(len(responseBytes))
	insertEvent("proxy", "transport_request_started", "attempt-1", map[string]any{"method": "POST", "uri": map[string]any{"path": "/v1/responses"}, "traffic_class": "model"}, nil, nil, "", "")
	insertEvent("proxy", "request_body_chunk", "attempt-1", map[string]any{"chunk_sequence": 1, "observed_size": requestSize}, requestDigest, &requestSize, "application/octet-stream", "")
	insertEvent("proxy", "request_body_finished", "attempt-1", map[string]any{}, nil, nil, "", "complete")
	insertEvent("proxy", "transport_response_started", "attempt-1", map[string]any{"status": 200}, nil, nil, "", "")
	insertEvent("proxy", "response_body_chunk", "attempt-1", map[string]any{"chunk_sequence": 1, "observed_size": responseSize}, responseDigest, &responseSize, "application/octet-stream", "")
	insertEvent("proxy", "transport_attempt_finished", "attempt-1", map[string]any{}, nil, nil, "", "complete")

	decoder := &stubTransportDecoder{
		expectedPcap: pcapBytes,
		expectedKeys: []byte{},
		result: &transportDecodeResult{Rows: 2, Streams: []decodedStream{{
			Protocol: "http/1.1", TCPStream: 1, Method: "POST", Path: "/v1/responses", Status: 200,
			Request:         bodyDigest{Bytes: requestSize, SHA256: digestForTest("hi"), Chunks: 1},
			Response:        bodyDigest{Bytes: responseSize, SHA256: digestForTest("ok"), Chunks: 1},
			EligibleForDiff: true,
		}}, Gaps: map[string]int64{}},
	}
	deps := &Deps{DB: db, Obj: objects, TransportDecoder: decoder}
	transportJob := &jobs.Job{ProjectID: project, Type: jobs.TypeTransportAudit, CaptureRunID: &run, ProcessorVersion: TransportAuditVersion}
	if err := deps.TransportAudit(ctx, transportJob); err != nil {
		t.Fatal(err)
	}
	var encodedProof json.RawMessage
	var proofRevision int64
	if err := db.Pool.QueryRow(ctx, `select transport_proof,transport_proof_revision from capture_runs where id=$1`, run).Scan(&encodedProof, &proofRevision); err != nil {
		t.Fatal(err)
	}
	var proof PlatformTransportProof
	if err := json.Unmarshal(encodedProof, &proof); err != nil {
		t.Fatal(err)
	}
	if proofRevision != 1 || !proof.Verified || proof.Status != "verified" || !proof.SourceBoundaryOK || !proof.PayloadDiffPassed || proof.MatchedAttempts != 1 || len(proof.Gaps) != 0 {
		t.Fatalf("platform proof was not verified: revision=%d proof=%+v", proofRevision, proof)
	}
	var coverageJobs int
	if err := db.Pool.QueryRow(ctx, `select count(*) from processing_jobs where capture_run_id=$1 and recording_id=$2 and type=$3 and processor_version=$4`, run, recording, jobs.TypeCoverage, CoverageVersion).Scan(&coverageJobs); err != nil {
		t.Fatal(err)
	}
	if coverageJobs != 1 {
		t.Fatalf("expected one version-bound coverage job, got %d", coverageJobs)
	}
	coverageJob := &jobs.Job{ProjectID: project, Type: jobs.TypeCoverage, RecordingID: &recording, CaptureRunID: &run, ProcessorVersion: CoverageVersion}
	if err := deps.Coverage(ctx, coverageJob); err != nil {
		t.Fatal(err)
	}
	var encodedCoverage json.RawMessage
	if err := db.Pool.QueryRow(ctx, `select coverage from recordings where id=$1`, recording).Scan(&encodedCoverage); err != nil {
		t.Fatal(err)
	}
	var coverage Coverage
	if err := json.Unmarshal(encodedCoverage, &coverage); err != nil {
		t.Fatal(err)
	}
	if !coverage.PlatformTransportProofVerified || coverage.PlatformTransportProofVersion != TransportAuditVersion || coverage.Claim != "client-complete" {
		t.Fatalf("coverage did not consume exact platform proof: %+v", coverage)
	}
	var coverageRulesJobs int
	if err := db.Pool.QueryRow(ctx, `select count(*) from processing_jobs where capture_run_id=$1 and type=$2 and input_ref->>'coverage_recording_id'=$3`, run, jobs.TypeRules, recording).Scan(&coverageRulesJobs); err != nil {
		t.Fatal(err)
	}
	if coverageRulesJobs != 1 {
		t.Fatalf("coverage did not schedule a final rules refresh: jobs=%d", coverageRulesJobs)
	}

	insertEvent("proxy", "request_body_finished", "", map[string]any{}, nil, nil, "", "complete")
	if err := deps.TransportAudit(ctx, transportJob); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select transport_proof,transport_proof_revision from capture_runs where id=$1`, run).Scan(&encodedProof, &proofRevision); err != nil {
		t.Fatal(err)
	}
	proof = PlatformTransportProof{}
	if err := json.Unmarshal(encodedProof, &proof); err != nil {
		t.Fatal(err)
	}
	if proofRevision != 2 || proof.Verified || proof.Status != "incomplete" || !proofContainsGap(proof.Gaps, "proxy_event_attempt_id_missing") {
		t.Fatalf("unattributed proxy evidence did not revoke verification: revision=%d proof=%+v", proofRevision, proof)
	}
	if err := deps.Coverage(ctx, coverageJob); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `select coverage from recordings where id=$1`, recording).Scan(&encodedCoverage); err != nil {
		t.Fatal(err)
	}
	coverage = Coverage{}
	if err := json.Unmarshal(encodedCoverage, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.PlatformTransportProofVerified || coverage.Claim != "best-effort" {
		t.Fatalf("coverage retained a complete claim after proof revocation: %+v", coverage)
	}
}

func proofContainsGap(gaps []ProofGap, want string) bool {
	for _, gap := range gaps {
		if gap.Reason == want {
			return true
		}
	}
	return false
}
