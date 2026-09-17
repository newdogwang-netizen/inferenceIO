package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
)

func TestProjectRateLimiterIsolatedBucketsAndMiddlewareResponse(t *testing.T) {
	limiter := NewProjectRateLimiter(60, 2)
	project := uuid.New()
	for range 2 {
		if ok, _ := limiter.Allow(project); !ok {
			t.Fatal("initial burst was rejected")
		}
	}
	if ok, retry := limiter.Allow(project); ok || retry <= 0 {
		t.Fatalf("exhausted bucket: allowed=%v retry=%s", ok, retry)
	}
	if ok, _ := limiter.Allow(uuid.New()); !ok {
		t.Fatal("one project exhausted another project's bucket")
	}

	handler := ProjectRateLimit(NewProjectRateLimiter(60, 1))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	principal := auth.Principal{Kind: auth.KindCollector, ProjectID: project}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(auth.WithPrincipal(t.Context(), principal)))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first request status=%d", first.Code)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(auth.WithPrincipal(t.Context(), principal)))
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
		t.Fatalf("limited response status=%d retry=%q", second.Code, second.Header().Get("Retry-After"))
	}
}
