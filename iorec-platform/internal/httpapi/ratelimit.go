package httpapi

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type projectBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

// ProjectRateLimiter is an in-process token bucket keyed by authenticated
// project. It bounds request pressure on a single API replica; multi-replica
// deployments must additionally enforce a shared limit at the ingress layer.
type ProjectRateLimiter struct {
	mu         sync.Mutex
	perSecond  float64
	burst      float64
	buckets    map[uuid.UUID]*projectBucket
	lastSweep  time.Time
	bucketIdle time.Duration
}

// NewProjectRateLimiter constructs a positive request-rate limit.
func NewProjectRateLimiter(requestsPerMinute, burst int) *ProjectRateLimiter {
	if requestsPerMinute <= 0 || burst <= 0 {
		panic("httpapi: project rate limit and burst must be positive")
	}
	now := time.Now()
	return &ProjectRateLimiter{
		perSecond:  float64(requestsPerMinute) / 60,
		burst:      float64(burst),
		buckets:    map[uuid.UUID]*projectBucket{},
		lastSweep:  now,
		bucketIdle: 10 * time.Minute,
	}
}

// Allow consumes one request token and returns a bounded retry delay when the
// project has exhausted its burst.
func (l *ProjectRateLimiter) Allow(project uuid.UUID) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= l.bucketIdle {
		for id, bucket := range l.buckets {
			if now.Sub(bucket.lastSeen) >= l.bucketIdle {
				delete(l.buckets, id)
			}
		}
		l.lastSweep = now
	}
	bucket := l.buckets[project]
	if bucket == nil {
		bucket = &projectBucket{tokens: l.burst, updated: now, lastSeen: now}
		l.buckets[project] = bucket
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	bucket.tokens = math.Min(l.burst, bucket.tokens+elapsed*l.perSecond)
	bucket.updated = now
	bucket.lastSeen = now
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true, 0
	}
	retry := time.Duration(math.Ceil((1 - bucket.tokens) / l.perSecond * float64(time.Second)))
	if retry < time.Second {
		retry = time.Second
	}
	if retry > time.Minute {
		retry = time.Minute
	}
	return false, retry
}

// ProjectRateLimit applies the limiter after authentication populated the
// principal. Retry-After is expressed as whole seconds for uploader clients.
func ProjectRateLimit(limiter *ProjectRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := Principal(r)
			if allowed, retry := limiter.Allow(principal.ProjectID); !allowed {
				seconds := int(math.Ceil(retry.Seconds()))
				w.Header().Set("Retry-After", strconv.Itoa(max(seconds, 1)))
				WriteError(w, r, E(http.StatusTooManyRequests, "rate_limited", "project request rate exceeded"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
