package jobs

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/heidihealth/iorec-platform/internal/store"
)

func TestCompleteClearsPriorRetryError(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	id, project := uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(ctx, `insert into processing_jobs(id,project_id,type,input_ref,processor_version,dedupe_key,status,last_error) values($1,$2,'rules','{}','test',$3,'leased','transient failure')`, id, project, "complete-test-"+id.String()); err != nil {
		t.Fatal(err)
	}
	if err := (&Queue{Pool: db.Pool}).Complete(ctx, id); err != nil {
		t.Fatal(err)
	}
	var status string
	var lastError *string
	if err := db.Pool.QueryRow(ctx, `select status,last_error from processing_jobs where id=$1`, id).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != StatusDone || lastError != nil {
		t.Fatalf("completed job retained failure state: status=%s last_error=%v", status, lastError)
	}
}
