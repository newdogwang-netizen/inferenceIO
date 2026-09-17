package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func apiError(t *testing.T, err error) *APIError {
	t.Helper()
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("not an API error: %v", err)
	}
	return api
}

func TestDecodeJSONEnforcesByteLimitAndOneValue(t *testing.T) {
	var value struct {
		Name string `json:"name"`
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}  `))
	if err := DecodeJSON(request, &value, 64); err != nil || value.Name != "ok" {
		t.Fatalf("valid JSON: value=%+v err=%v", value, err)
	}

	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{} {}`))
	if err := DecodeJSON(request, &value, 64); err == nil {
		t.Fatal("multiple JSON values were accepted")
	} else if got := apiError(t, err); got.Status != http.StatusBadRequest || got.Code != "bad_json" {
		t.Fatalf("unexpected trailing-value error: %+v", got)
	}

	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"too long"}`))
	if err := DecodeJSON(request, &value, 4); err == nil {
		t.Fatal("oversized JSON was accepted")
	} else if got := apiError(t, err); got.Status != http.StatusRequestEntityTooLarge || got.Code != "payload_too_large" {
		t.Fatalf("unexpected size error: %+v", got)
	}
}

func TestRequestIDRejectsUnboundedOrNonGraphicInput(t *testing.T) {
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(RequestID(r.Context())))
	}))

	for _, supplied := range []string{strings.Repeat("x", 129), "contains space"} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("X-Request-ID", supplied)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Body.String() == supplied || len(response.Body.String()) > 128 {
			t.Fatalf("unsafe request ID was reflected: %q", response.Body.String())
		}
		if response.Header().Get("X-Request-ID") != response.Body.String() {
			t.Fatal("response and context request IDs differ")
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Request-ID", "trace-123")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Body.String() != "trace-123" {
		t.Fatalf("safe request ID was not retained: %q", response.Body.String())
	}
}
