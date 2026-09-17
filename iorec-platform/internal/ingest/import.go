package ingest

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/protocol"
)

const (
	// MaxImportBytes bounds both the compressed request and expanded archive.
	MaxImportBytes int64 = 5 << 30
	// MaxImportEventBytes bounds the staged append-only event log without
	// requiring it to fit in memory.
	MaxImportEventBytes    int64 = 2 << 30
	MaxImportManifestBytes int64 = 16 << 20
	MaxImportEntries             = 300_000
	MaxImportBlobs               = 250_000
	MaxImportEvents              = 10_000_000
)

var errImportLimit = errors.New("import byte limit exceeded")

// ImportResult summarizes an offline import.
type ImportResult struct {
	RecordingID string `json:"recording_id"`
	CaptureRun  string `json:"capture_run_id"`
	Events      int    `json:"events"`
	Batches     int    `json:"batches"`
	Blobs       int    `json:"blobs"`
	DurableSeq  int64  `json:"durable_seq"`
	Sealed      bool   `json:"sealed"`
}

type stagedBlob struct {
	sha256 string
	path   string
}

type stagedImport struct {
	eventsPath  string
	manifest    json.RawMessage
	manifestSet bool
	blobs       []stagedBlob
	seenBlobs   map[string]struct{}
}

type importEventSummary struct {
	recordingID string
	runID       string
	events      int
	lastSeq     int64
}

// ImportRunDir ingests a tar (optionally gzip) of an iorec run directory. It
// stages bounded files in a private temporary directory and scans events in
// fixed batches, so a multi-gigabyte valid archive never becomes a
// multi-gigabyte heap allocation.
func (s *Service) ImportRunDir(ctx context.Context, p auth.Principal, input io.Reader, batchSize int) (*ImportResult, error) {
	if batchSize <= 0 || batchSize > protocol.MaxBatchEvents {
		batchSize = 500
	}
	stageDir, err := os.MkdirTemp("", "iorec-import-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stageDir)
	if err := os.Chmod(stageDir, 0o700); err != nil {
		return nil, err
	}

	staged, err := stageImportArchive(input, stageDir)
	if err != nil {
		return nil, err
	}
	if len(staged.manifest) > 0 && !json.Valid(staged.manifest) {
		return nil, httpapi.E(400, "malformed_request", "manifest.json is not valid JSON")
	}
	manifestRunID, recordingID, err := importManifestHints(staged.manifest)
	if err != nil {
		return nil, err
	}
	summary, err := validateImportEvents(staged.eventsPath, recordingID)
	if err != nil {
		return nil, err
	}
	if manifestRunID != "" && manifestRunID != summary.runID {
		return nil, httpapi.E(400, "malformed_request", "manifest and events use different run identifiers")
	}

	result := &ImportResult{RecordingID: summary.recordingID, CaptureRun: summary.runID}
	if err := s.CreateRecording(ctx, p, CreateRecordingRequest{
		RecordingID: summary.recordingID, CaptureRunID: summary.runID, SchemaVersion: 1,
	}); err != nil {
		return nil, err
	}
	if _, err := s.DB.Pool.Exec(ctx, `update recordings set origin='import' where id=$1 and origin='upload' and durable_seq=0`, summary.recordingID); err != nil {
		return nil, err
	}
	for _, blob := range staged.blobs {
		file, err := os.Open(blob.path)
		if err != nil {
			return nil, err
		}
		_, putErr := s.PutBlob(ctx, p, blob.sha256, "application/octet-stream", file)
		closeErr := file.Close()
		if putErr != nil {
			return nil, fmt.Errorf("blob %s: %w", blob.sha256, putErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		result.Blobs++
	}

	if err := s.uploadImportedEvents(ctx, p, staged.eventsPath, summary.recordingID, batchSize, result); err != nil {
		return nil, err
	}
	result.Events = summary.events
	if err := s.Seal(ctx, p, summary.recordingID, SealRequest{
		FinalSeq: summary.lastSeq, Manifest: staged.manifest,
	}); err != nil {
		return nil, err
	}
	result.Sealed = true
	return result, nil
}

func stageImportArchive(input io.Reader, stageDir string) (*stagedImport, error) {
	raw := &hardLimitReader{reader: input, remaining: MaxImportBytes}
	buffered := bufio.NewReader(raw)
	magic, err := buffered.Peek(2)
	if err != nil && err != io.EOF {
		return nil, importReadError(err)
	}
	var archive io.Reader = buffered
	var gzipReader *gzip.Reader
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, err = gzip.NewReader(buffered)
		if err != nil {
			return nil, httpapi.E(400, "malformed_request", "invalid gzip stream")
		}
		defer gzipReader.Close()
		archive = &hardLimitReader{reader: gzipReader, remaining: MaxImportBytes}
	}

	staged := &stagedImport{seenBlobs: make(map[string]struct{})}
	tarReader := tar.NewReader(archive)
	entries := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, importReadError(err)
		}
		entries++
		if entries > MaxImportEntries {
			return nil, httpapi.E(413, "payload_too_large", "archive entry count exceeds limit")
		}
		if header.Size < 0 {
			return nil, httpapi.E(400, "malformed_request", "archive entry has a negative size")
		}
		kind, value, err := classifyImportPath(header.Name)
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		switch kind {
		case "events":
			if staged.eventsPath != "" {
				return nil, httpapi.E(400, "malformed_request", "archive contains multiple events.jsonl files")
			}
			staged.eventsPath = filepath.Join(stageDir, "events.jsonl")
			if err := stageTarFile(tarReader, header.Size, MaxImportEventBytes, staged.eventsPath); err != nil {
				return nil, err
			}
		case "manifest":
			if staged.manifestSet {
				return nil, httpapi.E(400, "malformed_request", "archive contains multiple manifest.json files")
			}
			staged.manifest, err = readTarEntry(tarReader, header.Size, MaxImportManifestBytes)
			if err != nil {
				return nil, err
			}
			staged.manifestSet = true
		case "blob":
			if len(staged.blobs) >= MaxImportBlobs {
				return nil, httpapi.E(413, "payload_too_large", "archive blob count exceeds limit")
			}
			if !validLowerHexDigest(value) {
				return nil, httpapi.E(400, "malformed_request", "archive blob name has an invalid SHA-256")
			}
			if _, duplicate := staged.seenBlobs[value]; duplicate {
				return nil, httpapi.E(400, "malformed_request", "archive contains a duplicate blob digest")
			}
			blobPath := filepath.Join(stageDir, fmt.Sprintf("blob-%06d", len(staged.blobs)))
			if err := stageTarFile(tarReader, header.Size, MaxBlobBytes, blobPath); err != nil {
				return nil, err
			}
			staged.seenBlobs[value] = struct{}{}
			staged.blobs = append(staged.blobs, stagedBlob{sha256: value, path: blobPath})
		default:
			if _, err := io.Copy(io.Discard, tarReader); err != nil {
				return nil, importReadError(err)
			}
		}
	}
	if staged.eventsPath == "" {
		return nil, httpapi.E(400, "malformed_request", "archive has no events.jsonl")
	}
	return staged, nil
}

func classifyImportPath(name string) (kind, value string, err error) {
	if name == "" || path.IsAbs(name) || strings.ContainsRune(name, '\x00') {
		return "", "", httpapi.E(400, "malformed_request", "archive contains an unsafe path")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", "", httpapi.E(400, "malformed_request", "archive contains an unsafe path")
	}
	parts := strings.Split(clean, "/")
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", "", httpapi.E(400, "malformed_request", "archive contains an unsafe path")
		}
	}
	base := parts[len(parts)-1]
	switch {
	case base == "events.jsonl" && len(parts) <= 2:
		return "events", "", nil
	case base == "manifest.json" && len(parts) <= 2:
		return "manifest", "", nil
	case len(parts) >= 2 && len(parts) <= 3 && parts[len(parts)-2] == "blobs" && strings.HasPrefix(base, "sha256-"):
		return "blob", strings.TrimPrefix(base, "sha256-"), nil
	default:
		return "other", "", nil
	}
}

func stageTarFile(reader io.Reader, declaredSize, limit int64, destination string) error {
	if declaredSize > limit {
		return httpapi.E(413, "payload_too_large", "archive entry exceeds its size limit")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, reader)
	closeErr := file.Close()
	if copyErr != nil {
		return importReadError(copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if written != declaredSize {
		return httpapi.E(400, "malformed_request", "archive entry length does not match its header")
	}
	return nil
}

func readTarEntry(reader io.Reader, declaredSize, limit int64) ([]byte, error) {
	if declaredSize > limit {
		return nil, httpapi.E(413, "payload_too_large", "archive entry exceeds its size limit")
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, importReadError(err)
	}
	if int64(len(data)) != declaredSize {
		return nil, httpapi.E(400, "malformed_request", "archive entry length does not match its header")
	}
	return data, nil
}

func validateImportEvents(eventsPath, recordingID string) (*importEventSummary, error) {
	file, err := os.Open(eventsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	summary := &importEventSummary{}
	expectedSeq := int64(1)
	err = scanImportEvents(file, func(event protocol.Event) error {
		if summary.events == 0 {
			summary.runID = event.RunID
			summary.recordingID = recordingID
			if summary.recordingID == "" {
				summary.recordingID = recordingIDForRun(event.RunID)
			}
		}
		if event.RunID != summary.runID {
			return httpapi.E(400, "malformed_request", "events.jsonl mixes run identifiers")
		}
		if event.Seq != expectedSeq {
			return httpapi.E(400, "malformed_request", "events.jsonl sequence is not contiguous from one")
		}
		summary.events++
		if summary.events > MaxImportEvents {
			return httpapi.E(413, "payload_too_large", "import event count exceeds limit")
		}
		summary.lastSeq = event.Seq
		expectedSeq++
		return nil
	})
	if err != nil {
		return nil, err
	}
	if summary.events == 0 {
		return nil, httpapi.E(400, "malformed_request", "events.jsonl is empty")
	}
	return summary, nil
}

func importManifestHints(manifest json.RawMessage) (runID, recordingID string, err error) {
	if len(manifest) == 0 {
		return "", "", nil
	}
	var hints struct {
		RunID       string `json:"run_id"`
		RecordingID string `json:"recording_id"`
	}
	if err := json.Unmarshal(manifest, &hints); err != nil {
		return "", "", httpapi.E(400, "malformed_request", "manifest.json is not valid JSON")
	}
	if hints.RecordingID != "" && (len(hints.RecordingID) > 240 || strings.ContainsFunc(hints.RecordingID, unicode.IsControl)) {
		return "", "", httpapi.E(400, "malformed_request", "manifest recording_id is invalid")
	}
	return hints.RunID, hints.RecordingID, nil
}

func recordingIDForRun(runID string) string {
	const suffix = "#0000"
	if len(runID)+len(suffix) <= 240 {
		return runID + suffix
	}
	return "rec-" + protocol.SHA256Hex([]byte(runID)) + suffix
}

func (s *Service) uploadImportedEvents(ctx context.Context, p auth.Principal, eventsPath, recordingID string, batchSize int, result *ImportResult) error {
	file, err := os.Open(eventsPath)
	if err != nil {
		return err
	}
	defer file.Close()
	batch := make([]protocol.Event, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		refs := make([]protocol.BlobRef, 0, len(batch))
		for _, event := range batch {
			if event.PayloadRef != nil {
				refs = append(refs, protocol.BlobRef{SHA256: strings.TrimPrefix(event.PayloadRef.SHA256, "sha256:"), Size: event.PayloadRef.Size})
			}
		}
		header, compressed, err := protocol.EncodeBatch(batch, refs)
		if err != nil {
			return httpapi.E(400, "malformed_request", "events cannot form a bounded batch")
		}
		var body bytes.Buffer
		if err := protocol.WriteBatchBody(&body, header, compressed); err != nil {
			return err
		}
		ack, err := s.UploadBatch(ctx, p, recordingID, &body)
		if err != nil {
			return err
		}
		result.DurableSeq = ack.DurableSeq
		result.Batches++
		batch = batch[:0]
		return nil
	}
	if err := scanImportEvents(file, func(event protocol.Event) error {
		event.RecordingID = recordingID
		batch = append(batch, event)
		if len(batch) == batchSize {
			return flush()
		}
		return nil
	}); err != nil {
		return err
	}
	return flush()
}

func scanImportEvents(reader io.Reader, visit func(protocol.Event) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), protocol.MaxEventBytes+1)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		event, err := protocol.DecodeEvent(line)
		if err != nil {
			var decoded *protocol.DecodeError
			if errors.As(err, &decoded) && decoded.Code == "payload_too_large" {
				return httpapi.E(413, decoded.Code, decoded.Msg)
			}
			return httpapi.E(400, "malformed_request", "events.jsonl contains an invalid event")
		}
		if err := visit(event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return httpapi.E(413, "payload_too_large", "events.jsonl line exceeds limit")
	}
	return nil
}

func validLowerHexDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func importReadError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.Is(err, errImportLimit) || errors.As(err, &tooLarge) {
		return httpapi.E(413, "payload_too_large", "import archive exceeds its byte limit")
	}
	return httpapi.E(400, "malformed_request", "invalid tar archive")
}

type hardLimitReader struct {
	reader    io.Reader
	remaining int64
}

func (reader *hardLimitReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		var probe [1]byte
		count, err := reader.reader.Read(probe[:])
		if count > 0 {
			return 0, errImportLimit
		}
		return 0, err
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	count, err := reader.reader.Read(buffer)
	reader.remaining -= int64(count)
	return count, err
}
