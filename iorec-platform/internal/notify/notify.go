// Package notify implements the transactional outbox and the SSE fan-out.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Publish appends an outbox row inside tx.
func Publish(ctx context.Context, tx pgx.Tx, project uuid.UUID, entityType, entityID, kind string, revision int64) error {
	_, err := tx.Exec(ctx, `insert into notifications_outbox(project_id, entity_type, entity_id, kind, revision) values($1,$2,$3,$4,$5)`, project, entityType, entityID, kind, revision)
	return err
}

// PublishPool appends outside a transaction.
func PublishPool(ctx context.Context, pool *pgxpool.Pool, project uuid.UUID, entityType, entityID, kind string, revision int64) error {
	_, err := pool.Exec(ctx, `insert into notifications_outbox(project_id, entity_type, entity_id, kind, revision) values($1,$2,$3,$4,$5)`, project, entityType, entityID, kind, revision)
	return err
}

// Notification is one SSE event payload.
type Notification struct {
	ID         int64  `json:"id"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Kind       string `json:"kind"`
	Revision   *int64 `json:"revision,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// Fetch returns notifications after cursor.
func Fetch(ctx context.Context, pool *pgxpool.Pool, project uuid.UUID, cursor int64, limit int) ([]Notification, error) {
	rows, err := pool.Query(ctx, `select id, entity_type, entity_id, kind, revision, created_at from notifications_outbox where project_id=$1 and id > $2 order by id limit $3`, project, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var ts time.Time
		if err := rows.Scan(&n.ID, &n.EntityType, &n.EntityID, &n.Kind, &n.Revision, &ts); err != nil {
			return nil, err
		}
		n.CreatedAt = ts.UTC().Format(time.RFC3339Nano)
		out = append(out, n)
	}
	return out, rows.Err()
}

// StreamHandler serves text/event-stream for a project. Poll interval 1s; heartbeat 15s.
func StreamHandler(pool *pgxpool.Pool, project uuid.UUID, w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	cursor := int64(0)
	if c := r.URL.Query().Get("cursor"); c != "" {
		cursor, _ = strconv.ParseInt(c, 10, 64)
	} else if c := r.Header.Get("Last-Event-ID"); c != "" {
		cursor, _ = strconv.ParseInt(c, 10, 64)
	} else {
		// default: start from the latest id so clients only see new events
		_ = pool.QueryRow(r.Context(), `select coalesce(max(id),0) from notifications_outbox where project_id=$1`, project).Scan(&cursor)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, ": connected cursor=%d\n\n", cursor)
	fl.Flush()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-hb.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			fl.Flush()
		case <-tick.C:
			ns, err := Fetch(r.Context(), pool, project, cursor, 500)
			if err != nil {
				return
			}
			for _, n := range ns {
				b, _ := json.Marshal(n)
				fmt.Fprintf(w, "id: %d\nevent: entity.updated\ndata: %s\n\n", n.ID, b)
				cursor = n.ID
			}
			if len(ns) > 0 {
				fl.Flush()
			}
		}
	}
}
