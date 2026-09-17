package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
)

// BatchID derives the deterministic batch identifier from recording and seq range.
func BatchID(recordingID string, first, last int64) string {
	return fmt.Sprintf("%s:%012d-%012d", recordingID, first, last)
}

// BatchObjectKey is the object-store key of a batch (relative to the recording prefix).
func BatchObjectKey(first, last int64) string {
	return fmt.Sprintf("batches/%012d-%012d.ndjson.zst", first, last)
}

// SHA256Hex returns the lowercase hex digest.
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// EncodeBatch serializes events to ndjson, compresses with zstd and builds the header.
// Events must be non-empty, ordered and contiguous in seq, all for the same recording.
func EncodeBatch(events []Event, blobs []BlobRef) (BatchHeader, []byte, error) {
	if len(events) == 0 {
		return BatchHeader{}, nil, errors.New("encode: no events")
	}
	if len(events) > MaxBatchEvents {
		return BatchHeader{}, nil, fmt.Errorf("encode: event count exceeds %d", MaxBatchEvents)
	}
	if len(blobs) > MaxBatchBlobRefs {
		return BatchHeader{}, nil, fmt.Errorf("encode: blob reference count exceeds %d", MaxBatchBlobRefs)
	}
	var nd bytes.Buffer
	for i, ev := range events {
		if ev.RecordingID != events[0].RecordingID {
			return BatchHeader{}, nil, fmt.Errorf("encode: mixed recording_id at index %d", i)
		}
		if ev.RunID != events[0].RunID {
			return BatchHeader{}, nil, fmt.Errorf("encode: mixed run_id at index %d", i)
		}
		if i > 0 && ev.Seq != events[i-1].Seq+1 {
			return BatchHeader{}, nil, fmt.Errorf("encode: seq discontinuity at index %d (%d after %d)", i, ev.Seq, events[i-1].Seq)
		}
		line, err := json.Marshal(ev)
		if err != nil {
			return BatchHeader{}, nil, err
		}
		if len(line) > MaxEventBytes {
			return BatchHeader{}, nil, fmt.Errorf("encode: event at index %d exceeds %d bytes", i, MaxEventBytes)
		}
		if _, err := DecodeEvent(line); err != nil {
			return BatchHeader{}, nil, fmt.Errorf("encode: event at index %d is invalid: %w", i, err)
		}
		if nd.Len()+len(line)+1 > MaxBatchDecodedBytes {
			return BatchHeader{}, nil, fmt.Errorf("encode: decoded batch exceeds %d bytes", MaxBatchDecodedBytes)
		}
		nd.Write(line)
		nd.WriteByte('\n')
	}
	raw := nd.Bytes()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return BatchHeader{}, nil, err
	}
	compressed := enc.EncodeAll(raw, nil)
	_ = enc.Close()
	hdr := BatchHeader{
		BatchID:       BatchID(events[0].RecordingID, events[0].Seq, events[len(events)-1].Seq),
		RecordingID:   events[0].RecordingID,
		SchemaVersion: 1,
		FirstSeq:      events[0].Seq,
		LastSeq:       events[len(events)-1].Seq,
		EventCount:    len(events),
		ByteLength:    int64(len(raw)),
		SHA256:        SHA256Hex(raw),
		Encoding:      EncodingNDJSONZstd,
		Blobs:         blobs,
		CreatedAt:     time.Now().UTC(),
	}
	if err := ValidateHeaderRange(hdr); err != nil {
		return BatchHeader{}, nil, fmt.Errorf("encode: invalid header: %w", err)
	}
	return hdr, compressed, nil
}

// WriteBatchBody writes the wire form: header JSON line followed by compressed payload.
func WriteBatchBody(w io.Writer, hdr BatchHeader, compressed []byte) error {
	line, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	if _, err := w.Write(line); err != nil {
		return err
	}
	if _, err := w.Write([]byte{'\n'}); err != nil {
		return err
	}
	_, err = w.Write(compressed)
	return err
}

const (
	// MaxBatchBytes bounds a single upload body (header + compressed payload).
	MaxBatchBytes = 16 << 20
	// MaxBatchHeaderBytes prevents attacker-controlled metadata arrays from
	// consuming the entire body budget before payload validation.
	MaxBatchHeaderBytes = 1 << 20
	// MaxBatchDecodedBytes bounds zstd expansion and uncompressed NDJSON.
	MaxBatchDecodedBytes = 64 << 20
	// MaxEventBytes bounds one event before JSON decoding.
	MaxEventBytes = 16 << 20
	// MaxBatchEvents and MaxBatchBlobRefs bound decoded slice cardinality.
	MaxBatchEvents   = 10_000
	MaxBatchBlobRefs = 10_000
	maxJSONDepth     = 128
	maxJSONTokens    = 1_000_000
)

// DecodeError distinguishes client-side malformed input from other failures.
type DecodeError struct {
	Code string
	Msg  string
}

func (e *DecodeError) Error() string { return e.Code + ": " + e.Msg }

// ReadBatchBody splits and parses the wire form. It returns the header, the
// compressed payload bytes and the decompressed ndjson bytes.
func ReadBatchBody(r io.Reader) (BatchHeader, []byte, []byte, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, MaxBatchBytes+1), MaxBatchHeaderBytes+1)
	line, err := br.ReadBytes('\n')
	if err != nil {
		if len(line) > MaxBatchHeaderBytes {
			return BatchHeader{}, nil, nil, &DecodeError{"payload_too_large", "batch header exceeds limit"}
		}
		return BatchHeader{}, nil, nil, &DecodeError{"malformed_batch", "missing header line"}
	}
	if len(line) > MaxBatchHeaderBytes {
		return BatchHeader{}, nil, nil, &DecodeError{"payload_too_large", "batch header exceeds limit"}
	}
	hdr, err := decodeBatchHeader(line)
	if err != nil {
		return BatchHeader{}, nil, nil, err
	}
	compressed, err := io.ReadAll(br)
	if err != nil {
		return BatchHeader{}, nil, nil, err
	}
	if len(line)+len(compressed) > MaxBatchBytes {
		return BatchHeader{}, nil, nil, &DecodeError{"payload_too_large", "batch exceeds limit"}
	}
	var raw []byte
	switch hdr.Encoding {
	case EncodingNDJSONZstd:
		dec, err := zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(MaxBatchDecodedBytes),
			zstd.WithDecoderMaxWindow(MaxBatchDecodedBytes),
			zstd.WithDecodeAllCapLimit(true),
		)
		if err != nil {
			return BatchHeader{}, nil, nil, err
		}
		raw, err = dec.DecodeAll(compressed, make([]byte, 0, int(hdr.ByteLength)))
		dec.Close()
		if err != nil {
			return BatchHeader{}, nil, nil, &DecodeError{"payload_too_large", "zstd output exceeded its declared or configured limit"}
		}
	case EncodingNDJSON:
		raw = compressed
	default:
		return BatchHeader{}, nil, nil, &DecodeError{"malformed_batch", "unknown encoding"}
	}
	if int64(len(raw)) != hdr.ByteLength {
		return BatchHeader{}, nil, nil, &DecodeError{"malformed_batch", fmt.Sprintf("byte_length %d != actual %d", hdr.ByteLength, len(raw))}
	}
	if SHA256Hex(raw) != hdr.SHA256 {
		return BatchHeader{}, nil, nil, &DecodeError{"hash_mismatch", "sha256 of ndjson payload does not match header"}
	}
	return hdr, compressed, raw, nil
}

// ReadBatchHeader validates only the bounded first line. Retention uses this to
// recover references from published objects whose catalog transaction crashed.
func ReadBatchHeader(r io.Reader) (BatchHeader, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, MaxBatchHeaderBytes+1), MaxBatchHeaderBytes+1)
	line, err := br.ReadBytes('\n')
	if err != nil {
		if len(line) > MaxBatchHeaderBytes {
			return BatchHeader{}, &DecodeError{"payload_too_large", "batch header exceeds limit"}
		}
		return BatchHeader{}, &DecodeError{"malformed_batch", "missing header line"}
	}
	if len(line) > MaxBatchHeaderBytes {
		return BatchHeader{}, &DecodeError{"payload_too_large", "batch header exceeds limit"}
	}
	return decodeBatchHeader(line)
}

func decodeBatchHeader(line []byte) (BatchHeader, error) {
	if err := validateJSONComplexity(line); err != nil {
		return BatchHeader{}, &DecodeError{"malformed_batch", "header complexity: " + err.Error()}
	}
	var hdr BatchHeader
	if err := json.Unmarshal(line, &hdr); err != nil {
		return BatchHeader{}, &DecodeError{"malformed_batch", "header is not JSON: " + err.Error()}
	}
	var generic any
	_ = json.Unmarshal(line, &generic)
	if err := Validate(SchemaBatchV1, generic); err != nil {
		return BatchHeader{}, &DecodeError{"malformed_batch", "header schema: " + err.Error()}
	}
	if err := ValidateHeaderRange(hdr); err != nil {
		return BatchHeader{}, err
	}
	return hdr, nil
}

// ParseEvents decodes ndjson into events and validates each against the schema
// and the header's seq range / recording id.
func ParseEvents(hdr BatchHeader, raw []byte) ([]Event, error) {
	if len(raw) > MaxBatchDecodedBytes {
		return nil, &DecodeError{"payload_too_large", "decoded batch exceeds limit"}
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), MaxEventBytes+1)
	var out []Event
	expect := hdr.FirstSeq
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if len(out) >= MaxBatchEvents {
			return nil, &DecodeError{"payload_too_large", "event count exceeds limit"}
		}
		ev, err := DecodeEvent(line)
		if err != nil {
			if decoded, ok := err.(*DecodeError); ok {
				return nil, &DecodeError{decoded.Code, fmt.Sprintf("event at seq %d: %s", expect, decoded.Msg)}
			}
			return nil, err
		}
		if ev.Seq != expect {
			return nil, &DecodeError{"seq_discontinuity", fmt.Sprintf("expected seq %d, got %d", expect, ev.Seq)}
		}
		ev.RecordingID = hdr.RecordingID
		expect++
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, &DecodeError{"payload_too_large", "event line exceeds limit"}
	}
	if len(out) != hdr.EventCount || expect-1 != hdr.LastSeq {
		return nil, &DecodeError{"malformed_batch", fmt.Sprintf("event_count %d / last_seq %d do not match %d events ending at %d", hdr.EventCount, hdr.LastSeq, len(out), expect-1)}
	}
	return out, nil
}

// DecodeEvent validates the size, structural complexity, schema, and typed
// representation of one event line. Importers use the same gate as batches.
func DecodeEvent(line []byte) (Event, error) {
	if len(line) == 0 || len(line) > MaxEventBytes {
		return Event{}, &DecodeError{"payload_too_large", "event exceeds limit"}
	}
	if err := validateJSONComplexity(line); err != nil {
		return Event{}, &DecodeError{"malformed_batch", "event complexity: " + err.Error()}
	}
	var generic any
	if err := json.Unmarshal(line, &generic); err != nil {
		return Event{}, &DecodeError{"malformed_batch", "event is not JSON"}
	}
	if err := Validate(SchemaEventV1, generic); err != nil {
		return Event{}, &DecodeError{"malformed_batch", "event schema: " + err.Error()}
	}
	var event Event
	if err := json.Unmarshal(line, &event); err != nil {
		return Event{}, &DecodeError{"malformed_batch", err.Error()}
	}
	eventID, err := uuid.Parse(event.EventID)
	if err != nil || eventID.Version() != 7 || eventID.String() != event.EventID {
		return Event{}, &DecodeError{"malformed_batch", "event_id must be a canonical lowercase UUIDv7"}
	}
	return event, nil
}

// ValidateHeaderRange checks header-internal consistency.
func ValidateHeaderRange(h BatchHeader) error {
	if len(h.RecordingID) == 0 || len(h.RecordingID) > 240 || len(h.BatchID) == 0 || len(h.BatchID) > 512 {
		return &DecodeError{"malformed_batch", "batch or recording identifier exceeds limit"}
	}
	if h.EventCount <= 0 || h.EventCount > MaxBatchEvents {
		return &DecodeError{"payload_too_large", "event_count exceeds limit"}
	}
	if len(h.Blobs) > MaxBatchBlobRefs {
		return &DecodeError{"payload_too_large", "blob reference count exceeds limit"}
	}
	if h.ByteLength <= 0 || h.ByteLength > MaxBatchDecodedBytes {
		return &DecodeError{"payload_too_large", "byte_length exceeds decoded batch limit"}
	}
	if h.FirstSeq > h.LastSeq {
		return &DecodeError{"malformed_batch", "first_seq > last_seq"}
	}
	if int64(h.EventCount) != h.LastSeq-h.FirstSeq+1 {
		return &DecodeError{"malformed_batch", "event_count does not match seq range"}
	}
	if h.BatchID != BatchID(h.RecordingID, h.FirstSeq, h.LastSeq) {
		return &DecodeError{"malformed_batch", "batch_id does not match recording/seq range"}
	}
	return nil
}

func validateJSONComplexity(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	depth, tokens := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		tokens++
		if tokens > maxJSONTokens {
			return errors.New("JSON token count exceeds limit")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
				if depth > maxJSONDepth {
					return errors.New("JSON nesting exceeds limit")
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return errors.New("JSON delimiters are unbalanced")
				}
			}
		}
	}
	if depth != 0 {
		return errors.New("JSON delimiters are unbalanced")
	}
	return nil
}
