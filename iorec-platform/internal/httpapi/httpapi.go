// Package httpapi holds shared HTTP plumbing: JSON responses, error envelope,
// request ids, auth middleware.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/heidihealth/iorec-platform/internal/auth"
)

// APIError is the wire error envelope (platform/08 §5).
type APIError struct {
	Status    int            `json:"-"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// E builds an error.
func E(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg, Retryable: status == 429 || status >= 500}
}

// WithDetails attaches details.
func (e *APIError) WithDetails(d map[string]any) *APIError { e.Details = d; return e }

// WriteJSON writes v with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an error envelope, mapping unknown errors to 500.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *APIError
	if !errors.As(err, &ae) {
		slog.ErrorContext(r.Context(), "internal error", "err", err, "path", r.URL.Path, "request_id", RequestID(r.Context()))
		ae = E(http.StatusInternalServerError, "internal", "internal error")
	}
	if ae.Status == http.StatusTooManyRequests || ae.Status == http.StatusServiceUnavailable {
		if w.Header().Get("Retry-After") == "" {
			w.Header().Set("Retry-After", "5")
		}
	}
	WriteJSON(w, ae.Status, map[string]any{"error": ae})
}

// DecodeJSON reads a bounded JSON body.
func DecodeJSON(r *http.Request, v any, limit int64) error {
	if limit <= 0 {
		return E(http.StatusInternalServerError, "internal", "invalid request limit")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return E(http.StatusBadRequest, "bad_json", "could not read request body")
	}
	if int64(len(body)) > limit {
		return E(http.StatusRequestEntityTooLarge, "payload_too_large", "request body exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return E(http.StatusBadRequest, "bad_json", "request body is not valid JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return E(http.StatusBadRequest, "bad_json", "request body must contain exactly one JSON value")
	}
	return nil
}

type ridKey struct{}

// RequestID returns the request id.
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(ridKey{}).(string)
	return s
}

// RequestIDMiddleware assigns X-Request-ID.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 || strings.IndexFunc(id, func(char rune) bool {
			return char < 0x21 || char > 0x7e
		}) >= 0 {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ridKey{}, id)))
	})
}

// Logging logs each request.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds(), "request_id", RequestID(r.Context()))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Authenticate resolves the principal or 401s.
func Authenticate(a *auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := a.Resolve(r)
			if err != nil {
				if errors.Is(err, auth.ErrUnauthorized) {
					WriteError(w, r, E(http.StatusUnauthorized, "unauthorized", "missing or invalid credentials"))
					return
				}
				WriteError(w, r, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
		})
	}
}

// Principal fetches the principal or panics (handlers are always behind Authenticate).
func Principal(r *http.Request) auth.Principal {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		panic("httpapi: no principal in context")
	}
	return p
}

// RequireUser ensures a user with at least role.
func RequireUser(r *http.Request, role string) (auth.Principal, error) {
	p := Principal(r)
	if p.Kind != auth.KindUser {
		return p, E(http.StatusForbidden, "forbidden", "user credential required")
	}
	if !p.HasRole(role) {
		return p, E(http.StatusForbidden, "forbidden", "requires role "+role)
	}
	return p, nil
}

// RequireCollector ensures a collector/project credential.
func RequireCollector(r *http.Request) (auth.Principal, error) {
	p := Principal(r)
	if p.Kind != auth.KindCollector {
		return p, E(http.StatusForbidden, "forbidden", "collector credential required")
	}
	return p, nil
}
