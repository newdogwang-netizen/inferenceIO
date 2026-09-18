package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Heartbeat records process/database liveness, including when no jobs exist.
// Separate job states remain the source of processing success and drain status.
func Heartbeat(ctx context.Context, pool *pgxpool.Pool, owner string, pools map[string]int) {
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanup, `delete from worker_heartbeats where owner=$1`, owner)
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := pool.Exec(probe, `insert into worker_heartbeats(owner,pools) values($1,$2) on conflict(owner) do update set pools=excluded.pools,last_seen_at=now()`, owner, pools)
		if err == nil {
			_, err = pool.Exec(probe, `delete from worker_heartbeats where last_seen_at<now()-interval '1 day'`)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("worker heartbeat failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
