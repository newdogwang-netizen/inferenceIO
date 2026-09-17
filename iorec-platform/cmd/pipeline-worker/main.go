// pipeline-worker leases processing jobs and runs the pipeline stages.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/jobs"
	"github.com/heidihealth/iorec-platform/internal/objstore"
	"github.com/heidihealth/iorec-platform/internal/pipeline"
	"github.com/heidihealth/iorec-platform/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
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
	var obj objstore.Store
	if ep := os.Getenv("OBJECT_STORE_ENDPOINT"); ep != "" {
		obj, err = objstore.NewS3(ctx, objstore.S3Config{Endpoint: ep, Bucket: env("OBJECT_STORE_BUCKET", "iorec"), AccessKey: os.Getenv("OBJECT_STORE_ACCESS_KEY"), SecretKey: os.Getenv("OBJECT_STORE_SECRET_KEY"), Region: env("OBJECT_STORE_REGION", "us-east-1")})
	} else {
		obj, err = objstore.NewFS(env("OBJECT_STORE_DIR", "./data/objects"))
	}
	if err != nil {
		slog.Error("objstore", "err", err)
		os.Exit(1)
	}
	var transportDecoder pipeline.TransportDecoder
	if tsharkPath := os.Getenv("IOREC_TSHARK_PATH"); tsharkPath != "" {
		transportDecoder, err = pipeline.NewTSharkDecoder(ctx, tsharkPath)
		if err != nil {
			slog.Error("tshark", "err", err)
			os.Exit(1)
		}
	}
	deps := &pipeline.Deps{DB: db, Obj: obj, TransportDecoder: transportDecoder}
	host, _ := os.Hostname()
	owner := fmt.Sprintf("%s/%s", host, uuid.NewString()[:8])

	// WORKER_POOLS="decode=4,assemble=4,normalize=2,resolve=2,transport_audit=1,coverage=1,rules=1,export=1"
	pools := map[string]int{jobs.TypeDecode: 4, jobs.TypeAssemble: 4, jobs.TypeNormalize: 2, jobs.TypeResolve: 2, jobs.TypeTransportAudit: 1, jobs.TypeCoverage: 1, jobs.TypeRules: 1, jobs.TypeExport: 1}
	for _, kv := range strings.Split(os.Getenv("WORKER_POOLS"), ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			if n, err := strconv.Atoi(v); err == nil {
				pools[k] = n
			}
		}
	}
	var wg sync.WaitGroup
	for typ, n := range pools {
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(typ string, i int) {
				defer wg.Done()
				q := &jobs.Queue{Pool: db.Pool, Owner: fmt.Sprintf("%s/%s-%d", owner, typ, i), LeaseFor: 5 * time.Minute}
				loop(ctx, q, deps, []string{typ})
			}(typ, i)
		}
	}
	slog.Info("pipeline-worker started", "owner", owner, "pools", pools)
	wg.Wait()
}

func loop(ctx context.Context, q *jobs.Queue, deps *pipeline.Deps, types []string) {
	idle := 250 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		j, err := q.Lease(ctx, types)
		if err != nil {
			slog.Warn("lease", "err", err)
			sleep(ctx, 2*time.Second)
			continue
		}
		if j == nil {
			sleep(ctx, idle)
			if idle < 2*time.Second {
				idle *= 2
			}
			continue
		}
		idle = 250 * time.Millisecond
		jctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		done := make(chan struct{})
		go func() { // lease renewal
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					_ = q.Renew(context.Background(), j.ID)
				}
			}
		}()
		err = deps.Handle(jctx, j)
		close(done)
		cancel()
		if err != nil {
			slog.Warn("job failed", "type", j.Type, "id", j.ID, "attempt", j.Attempts, "err", err)
			_ = q.Fail(context.Background(), j, err)
			continue
		}
		_ = q.Complete(context.Background(), j.ID)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
