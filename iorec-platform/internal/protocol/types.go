package protocol

import (
	"encoding/json"
	"time"
)

// Source values.
const (
	SourceRunner      = "runner"
	SourceProxy       = "proxy"
	SourceHook        = "hook"
	SourceSDK         = "sdk"
	SourceSessionFile = "session_file"
	SourceEBPF        = "ebpf"
	SourceKeylog      = "keylog"
	SourcePTY         = "pty"
	SourceObserver    = "observer"
)

// Event names (subset used by the platform pipeline directly).
const (
	EvRunStart         = "run_start"
	EvRunEnd           = "run_end"
	EvProcessStart     = "process_start"
	EvProcessExit      = "process_exit"
	EvCapabilityReport = "capability_report"
	EvGap              = "gap"
	EvSessionStart     = "session_start"
	EvSessionEnd       = "session_end"
	EvTurnStart        = "turn_start"
	EvTurnEnd          = "turn_end"
	EvToolCall         = "tool_call"
	EvToolResult       = "tool_result"
	EvSubagentStart    = "subagent_start"
	EvSubagentStop     = "subagent_stop"
	EvCompaction       = "compaction"
	EvInferenceRequest = "inference_request"
	EvInferenceResp    = "inference_response"
	EvInferenceError   = "inference_error"
	EvAttemptStart     = "attempt_start"
	EvRequestHeaders   = "request_headers"
	EvRequestBody      = "request_body"
	EvResponseHeaders  = "response_headers"
	EvSSEChunk         = "sse_chunk"
	EvWSFrame          = "ws_frame"
	EvResponseBody     = "response_body"
	EvAttemptEnd       = "attempt_end"
	EvAttemptError     = "attempt_error"
	EvAttemptCancel    = "attempt_cancel"
	EvConnectionOpen   = "connection_open"
	EvConnectionClose  = "connection_close"
	EvDropCounter      = "drop_counter"
	EvUnknownEgress    = "unknown_egress"
	EvTLSSurface       = "tls_surface"
	EvManifest         = "manifest"

	// Recorder-native names. The local recorder envelope is the shared wire
	// contract; the earlier semantic aliases above remain readable for batches
	// produced by pre-freeze fake collectors.
	EvRunStarted               = "run_started"
	EvRunFinished              = "run_finished"
	EvTransportRequestStarted  = "transport_request_started"
	EvRequestBodyChunk         = "request_body_chunk"
	EvRequestBodyFinished      = "request_body_finished"
	EvTransportResponseStarted = "transport_response_started"
	EvResponseBodyChunk        = "response_body_chunk"
	EvSSEEvent                 = "sse_event"
	EvTransportAttemptFinished = "transport_attempt_finished"
	EvWebSocketFrame           = "websocket_frame"
)

// IDs carries the identifiers the capture side knows for certain.
type IDs struct {
	TaskID         string `json:"task_id,omitempty"`
	AgentSessionID string `json:"session_id,omitempty"`
	TurnID         string `json:"turn_id,omitempty"`
	InferenceID    string `json:"inference_id,omitempty"`
	AttemptID      string `json:"attempt_id,omitempty"`
	ConnectionID   string `json:"connection_id,omitempty"`
	ParentSpanID   string `json:"parent_id,omitempty"`
	PID            int    `json:"pid,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
}

// PayloadRef points at a content-addressed blob.
type PayloadRef struct {
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Redaction records what the capture side removed or replaced.
type Redaction struct {
	Policy  string   `json:"policy,omitempty"`
	Fields  []string `json:"fields,omitempty"`
	Omitted []string `json:"omitted,omitempty"`
}

// Event is the v1 envelope.
type Event struct {
	SchemaVersion int    `json:"schema_version"`
	EventID       string `json:"event_id"`
	Seq           int64  `json:"sequence"`
	RunID         string `json:"run_id"`
	RecordingID   string `json:"-"`
	IDs
	Source        string          `json:"source"`
	Event         string          `json:"event"`
	MonotonicNS   int64           `json:"monotonic_ns"`
	WallTime      time.Time       `json:"wall_time"`
	PayloadRef    *PayloadRef     `json:"raw,omitempty"`
	Payload       json.RawMessage `json:"normalized,omitempty"`
	Redaction     *Redaction      `json:"redaction"`
	Confidence    *float64        `json:"confidence,omitempty"`
	Evidence      []string        `json:"evidence,omitempty"`
	TerminalState string          `json:"terminal_state,omitempty"`
}

// BlobRef is a blob referenced by a batch.
type BlobRef struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// BatchHeader is the first line of a batch upload body.
type BatchHeader struct {
	BatchID       string    `json:"batch_id"`
	RecordingID   string    `json:"recording_id"`
	SchemaVersion int       `json:"schema_version"`
	FirstSeq      int64     `json:"first_seq"`
	LastSeq       int64     `json:"last_seq"`
	EventCount    int       `json:"event_count"`
	ByteLength    int64     `json:"byte_length"`
	SHA256        string    `json:"sha256"`
	PrevSHA256    string    `json:"prev_sha256,omitempty"`
	Encoding      string    `json:"encoding"`
	Blobs         []BlobRef `json:"blobs,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Encodings.
const (
	EncodingNDJSONZstd = "ndjson+zstd"
	EncodingNDJSON     = "ndjson"
)

// ContentTypeBatch is the media type of a batch upload body.
const ContentTypeBatch = "application/vnd.iorec.batch+zstd"
