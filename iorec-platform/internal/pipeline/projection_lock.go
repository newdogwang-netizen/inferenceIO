package pipeline

import (
	"context"
	"time"
)

// Serialize normalization and resolution for one run across worker replicas.
// Waiting jobs do not pin pool connections (which could otherwise deadlock a
// saturated pool). The session lock is released on every error/cancellation.
func (d *Deps) lockProjection(ctx context.Context, run string) (func(), error) {
	key := "iorec-call-projection:" + run
	for {
		conn, err := d.DB.Pool.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		var locked bool
		err = conn.QueryRow(ctx, `select pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&locked)
		if err != nil {
			// A cancelled query may have acquired the lock before cancellation.
			_ = conn.Conn().Close(context.Background())
			conn.Release()
			return nil, err
		}
		if locked {
			return func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var unlocked bool
				if err := conn.QueryRow(cleanup, `select pg_advisory_unlock(hashtextextended($1,0))`, key).Scan(&unlocked); err != nil || !unlocked {
					_ = conn.Conn().Close(cleanup)
				}
				conn.Release()
			}, nil
		}
		conn.Release()
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
