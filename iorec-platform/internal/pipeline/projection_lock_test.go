package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProjectionLockCancellationAndRunIsolation(t *testing.T) {
	d := &Deps{DB: pipelineTestDB(t)}
	run := "lock-test-" + uuid.NewString()
	unlock, err := d.lockProjection(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := d.lockProjection(ctx, run); !errors.Is(err, context.DeadlineExceeded) {
		unlock()
		t.Fatalf("same-run lock not cancelled: %v", err)
	}
	other, err := d.lockProjection(context.Background(), run+"-other")
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	other()
	unlock()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	final, err := d.lockProjection(ctx2, run)
	if err != nil {
		t.Fatal("projection lock leaked after cancellation", err)
	}
	final()
}
