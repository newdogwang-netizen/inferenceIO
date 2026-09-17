// platform-api: receives data-plane uploads, serves the control plane and the
// console read API, and streams notifications.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/control"
	"github.com/heidihealth/iorec-platform/internal/exporter"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
	"github.com/heidihealth/iorec-platform/internal/ingest"
	"github.com/heidihealth/iorec-platform/internal/notify"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/query"
	"github.com/heidihealth/iorec-platform/internal/retention"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func durationEnv(key, fallback string) time.Duration {
	raw := env(key, fallback)
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 {
		slog.Error("invalid duration configuration", "key", key, "value", raw, "err", err)
		os.Exit(2)
	}
	return duration
}

func positiveIntEnv(key string, fallback int) int {
	raw := env(key, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		slog.Error("invalid positive integer configuration", "key", key, "value", raw, "err", err)
		os.Exit(2)
	}
	return value
}

func positiveInt64Env(key string, fallback int64) int64 {
	raw := env(key, strconv.FormatInt(fallback, 10))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		slog.Error("invalid positive integer configuration", "key", key, "value", raw, "err", err)
		os.Exit(2)
	}
	return value
}

func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, env("DATABASE_URL", "postgres://iorec:iorec@127.0.0.1:54329/iorec"))
	if err != nil {
		slog.Error("db", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		slog.Error("migrate", "err", err)
		os.Exit(1)
	}
	obj, err := openObjStore(ctx)
	if err != nil {
		slog.Error("objstore", "err", err)
		os.Exit(1)
	}
	tenantID := uuid.MustParse(env("IOREC_DEFAULT_TENANT_ID", "00000000-0000-0000-0000-000000000001"))
	projectID := uuid.MustParse(env("IOREC_DEFAULT_PROJECT_ID", "00000000-0000-0000-0000-000000000002"))
	authCfg := auth.Config{Mode: env("IOREC_AUTH_MODE", "dev"), DefaultTenantID: tenantID, DefaultProjectID: projectID, UserTokens: map[string]string{}}
	if authCfg.Mode != "dev" && authCfg.Mode != "token" && authCfg.Mode != "oidc" {
		slog.Error("invalid auth mode", "mode", authCfg.Mode)
		os.Exit(2)
	}
	for _, kv := range strings.Split(os.Getenv("IOREC_USER_TOKENS"), ",") {
		if tok, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			authCfg.UserTokens[tok] = v
		}
	}
	issuer := os.Getenv("IOREC_OIDC_ISSUER")
	clientID := os.Getenv("IOREC_OIDC_CLIENT_ID")
	if authCfg.Mode == "oidc" && (issuer == "" || clientID == "") {
		slog.Error("oidc mode requires IOREC_OIDC_ISSUER and IOREC_OIDC_CLIENT_ID")
		os.Exit(2)
	}
	if issuer != "" {
		if clientID == "" {
			slog.Error("IOREC_OIDC_CLIENT_ID is required when an OIDC issuer is configured")
			os.Exit(2)
		}
		v, err := auth.NewOIDC(ctx, issuer, clientID)
		if err != nil {
			slog.Error("oidc", "err", err)
			os.Exit(1)
		}
		authCfg.OIDC = v
	}
	if err := auth.Bootstrap(ctx, db.Pool, authCfg, os.Getenv("IOREC_BOOTSTRAP_PROJECT_TOKEN")); err != nil {
		slog.Error("bootstrap", "err", err)
		os.Exit(1)
	}
	authn := &auth.Authenticator{Pool: db.Pool, Cfg: authCfg}
	ing := &ingest.Service{
		DB:                     db,
		Obj:                    obj,
		MaxProjectStorageBytes: positiveInt64Env("IOREC_PROJECT_STORAGE_BYTES", ingest.DefaultMaxProjectStorageBytes),
	}
	ctl := &control.Service{DB: db}
	exp := &exporter.Service{DB: db, Obj: obj}
	qs := &query.Service{DB: db}
	ret := &retention.Service{DB: db, Obj: obj}
	projectRateLimiter := httpapi.NewProjectRateLimiter(
		positiveIntEnv("IOREC_PROJECT_REQUESTS_PER_MINUTE", 6000),
		positiveIntEnv("IOREC_PROJECT_REQUEST_BURST", 200),
	)

	// Background lifecycle sweeps. Retention uses its own short cadence so large
	// object sets converge without coupling collector liveness to object-store latency.
	autoSeal := durationEnv("IOREC_AUTO_SEAL_AFTER", "24h")
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := ctl.SweepStatus(ctx, autoSeal); err != nil {
					slog.Warn("sweep", "err", err)
				}
				_ = ctl.ExpireRequests(ctx)
				if err := exp.SweepExpired(ctx); err != nil {
					slog.Warn("export expiry sweep", "err", err)
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := ret.Sweep(ctx); err != nil {
					slog.Warn("retention sweep", "err", err)
				}
			}
		}
	}()

	r := chi.NewRouter()
	r.Use(httpapi.RequestIDMiddleware, httpapi.Logging, middleware.Recoverer)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Pool.Ping(r.Context()); err != nil {
			slog.WarnContext(r.Context(), "health check database failure", "err", err, "request_id", httpapi.RequestID(r.Context()))
			httpapi.WriteError(w, r, httpapi.E(503, "db_unavailable", "database unavailable"))
			return
		}
		httpapi.WriteJSON(w, 200, map[string]any{"ok": true})
	})
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpapi.Authenticate(authn))
		r.Use(httpapi.ProjectRateLimit(projectRateLimiter))
		r.Get("/me", qs.Me)
		r.Get("/overview", qs.Overview)

		// data plane
		r.Post("/recordings", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			var req ingest.CreateRecordingRequest
			if err := httpapi.DecodeJSON(r, &req, 1<<20); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			if err := ing.CreateRecording(r.Context(), p, req); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 201, map[string]any{"recording_id": req.RecordingID, "state": "open"})
		})
		r.Post("/recordings/{id}/batches", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			res, err := ing.UploadBatch(r.Context(), p, chi.URLParam(r, "id"), r.Body)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, res)
		})
		r.Post("/recordings/{id}:seal", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			var req ingest.SealRequest
			if err := httpapi.DecodeJSON(r, &req, 4<<20); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			if err := ing.Seal(r.Context(), p, chi.URLParam(r, "id"), req); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, map[string]any{"state": "sealed"})
		})
		r.Post("/recordings:import", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleOperator)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			body := http.MaxBytesReader(w, r.Body, ingest.MaxImportBytes)
			defer body.Close()
			res, err := ing.ImportRunDir(r.Context(), p, body, 500)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 201, res)
		})
		r.Post("/exports", exp.Create)
		r.Get("/exports", exp.List)
		r.Get("/exports/{id}", exp.Get)
		r.Get("/exports/{id}/download", exp.Download)
		r.Head("/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
			ok, size, err := ing.BlobExists(r.Context(), httpapi.Principal(r), chi.URLParam(r, "sha"))
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.WriteHeader(200)
		})
		r.Put("/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			created, err := ing.PutBlob(r.Context(), p, chi.URLParam(r, "sha"), r.Header.Get("Content-Type"), r.Body)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			status := 200
			if created {
				status = 201
			}
			httpapi.WriteJSON(w, status, map[string]any{"sha256": chi.URLParam(r, "sha"), "created": created})
		})
		r.Get("/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleViewer)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			rc, mt, err := ing.OpenBlob(r.Context(), p.ProjectID, p.TenantID, chi.URLParam(r, "sha"))
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			defer rc.Close()
			if p.Kind == auth.KindUser {
				if _, err := db.Pool.Exec(r.Context(), `insert into audit_log(project_id, subject, action, entity_type, entity_id, detail) values($1,$2,'blob.read','blob',$3,'{}'::jsonb)`, p.ProjectID, p.Subject, chi.URLParam(r, "sha")); err != nil {
					httpapi.WriteError(w, r, err)
					return
				}
			}
			w.Header().Set("Content-Type", mt)
			w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
			_, _ = io.Copy(w, rc)
		})

		// control plane
		r.Post("/collectors:register", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			var req control.RegisterRequest
			if err := httpapi.DecodeJSON(r, &req, 1<<20); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			res, err := ctl.Register(r.Context(), p, req)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, res)
		})
		r.Post("/collectors/{id}:heartbeat", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "bad collector id"))
				return
			}
			var req control.HeartbeatRequest
			if err := httpapi.DecodeJSON(r, &req, 1<<20); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			res, err := ctl.Heartbeat(r.Context(), p, id, req)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, res)
		})
		r.Put("/projects/current/collector-config", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleOperator)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			var req control.ConfigUpdate
			if err := httpapi.DecodeJSON(r, &req, 256<<10); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			version, err := ctl.SetProjectConfig(r.Context(), p, req)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, map[string]any{"config_version": version})
		})
		r.Put("/collectors/{id}/config", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleOperator)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "bad collector id"))
				return
			}
			var req control.ConfigUpdate
			if err := httpapi.DecodeJSON(r, &req, 256<<10); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			response, err := ctl.SetCollectorConfig(r.Context(), p, id, req)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, response)
		})
		r.Delete("/collectors/{id}/config", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleOperator)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "bad collector id"))
				return
			}
			response, err := ctl.ClearCollectorConfig(r.Context(), p, id)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, response)
		})
		r.Get("/collectors", qs.ListCollectors)
		r.Get("/collector-requests", func(w http.ResponseWriter, r *http.Request) {
			p := httpapi.Principal(r)
			if p.Kind == auth.KindCollector {
				wait, _ := time.ParseDuration(env("X", r.URL.Query().Get("wait")))
				if wait <= 0 || wait > 60*time.Second {
					wait = 0
				}
				items, err := ctl.Poll(r.Context(), p, wait)
				if err != nil {
					httpapi.WriteError(w, r, err)
					return
				}
				httpapi.WriteJSON(w, 200, map[string]any{"items": items})
				return
			}
			qs.ListCollectorRequests(w, r)
		})
		r.Post("/collector-requests", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleOperator)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			var req control.CreateRequest
			if err := httpapi.DecodeJSON(r, &req, 1<<20); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			id, err := ctl.CreateCollectorRequest(r.Context(), p, req)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 201, map[string]any{"id": id, "status": "pending"})
		})
		r.Post("/collector-requests/{id}:result", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireCollector(r)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpapi.WriteError(w, r, httpapi.E(400, "malformed_request", "bad request id"))
				return
			}
			var req control.ResultRequest
			if err := httpapi.DecodeJSON(r, &req, 1<<20); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			if err := ctl.Report(r.Context(), p, id, req); err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			httpapi.WriteJSON(w, 200, map[string]any{"id": id, "status": req.Status})
		})

		// read models
		r.Get("/recordings", qs.ListRecordings)
		r.Get("/recordings/{id}", qs.GetRecording)
		r.Delete("/recordings/{id}", ret.DeleteHandler("recording"))
		r.Get("/recordings/{id}/timeline", qs.Timeline)
		r.Get("/recordings/{id}/events", qs.Events)
		r.Get("/recordings/{id}/coverage", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleViewer)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			var cov []byte
			err = db.Pool.QueryRow(r.Context(), `select coalesce(r.coverage::text,'null') from recordings r join capture_runs c on c.id=r.capture_run_id and c.project_id=r.project_id where r.id=$1 and r.project_id=$2 and c.state='active' and r.state not in ('deleting','deleted')`, chi.URLParam(r, "id"), p.ProjectID).Scan(&cov)
			if err != nil {
				httpapi.WriteError(w, r, httpapi.E(404, "not_found", "unknown recording"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cov)
		})
		r.Get("/capture-runs", qs.ListRuns)
		r.Delete("/capture-runs/{id}", ret.DeleteHandler("capture_run"))
		r.Get("/attempts", qs.ListAttempts)
		r.Get("/attempts/{id}", qs.GetAttempt)
		r.Get("/inferences/{id}", qs.GetInference)
		r.Get("/sessions/{id}", qs.GetSession)
		r.Delete("/sessions/{id}", ret.DeleteHandler("session"))
		r.Get("/deletions", ret.List)
		r.Get("/deletions/{id}", ret.Get)
		r.Post("/deletions/{id}:retry-local", ret.RetryLocal)
		r.Get("/projects/current/retention", ret.GetPolicy)
		r.Put("/projects/current/retention", ret.SetPolicy)
		r.Get("/findings", qs.ListFindings)
		r.Post("/findings/{id}:review", qs.ReviewFinding)
		r.Get("/processing-jobs", qs.ListJobs)
		r.Post("/processing-jobs", qs.CreateJob)
		r.Post("/processing-jobs/{id}:retry", qs.RetryJob)
		r.Get("/notifications/stream", func(w http.ResponseWriter, r *http.Request) {
			p, err := httpapi.RequireUser(r, auth.RoleViewer)
			if err != nil {
				httpapi.WriteError(w, r, err)
				return
			}
			notify.StreamHandler(db.Pool, p.ProjectID, w, r)
		})
	})

	// Optional: serve the built console from the API process (single-binary demo / small deployments).
	if webDir := os.Getenv("IOREC_WEB_DIR"); webDir != "" {
		fs := http.FileServer(http.Dir(webDir))
		r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
			p := filepath.Join(webDir, filepath.Clean("/"+req.URL.Path))
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				fs.ServeHTTP(w, req)
				return
			}
			http.ServeFile(w, req, filepath.Join(webDir, "index.html"))
		})
	}

	defaultAddr := ":8080"
	if authCfg.Mode == "dev" {
		defaultAddr = "127.0.0.1:8080"
	}
	addr := env("IOREC_API_ADDR", defaultAddr)
	if authCfg.Mode == "dev" && !loopbackAddress(addr) && os.Getenv("IOREC_ALLOW_REMOTE_DEV_AUTH") != "true" {
		slog.Error("refusing to expose unauthenticated dev mode on a non-loopback address", "addr", addr)
		os.Exit(2)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: durationEnv("IOREC_HTTP_READ_HEADER_TIMEOUT", "10s"),
		ReadTimeout:       durationEnv("IOREC_HTTP_READ_TIMEOUT", "30m"),
		IdleTimeout:       durationEnv("IOREC_HTTP_IDLE_TIMEOUT", "2m"),
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("platform-api listening", "addr", addr, "auth_mode", authCfg.Mode)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

func openObjStore(ctx context.Context) (objstore.Store, error) {
	if ep := os.Getenv("OBJECT_STORE_ENDPOINT"); ep != "" {
		return objstore.NewS3(ctx, objstore.S3Config{Endpoint: ep, Bucket: env("OBJECT_STORE_BUCKET", "iorec"), AccessKey: os.Getenv("OBJECT_STORE_ACCESS_KEY"), SecretKey: os.Getenv("OBJECT_STORE_SECRET_KEY"), Region: env("OBJECT_STORE_REGION", "us-east-1")})
	}
	root := env("OBJECT_STORE_DIR", "./data/objects")
	fs, err := objstore.NewFS(root)
	if err != nil {
		return nil, fmt.Errorf("fs objstore %s: %w", root, err)
	}
	return fs, nil
}
