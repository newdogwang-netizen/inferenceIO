package objstore

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFSRejectsUnsafeKeysAndNeverReplacesObjects(t *testing.T) {
	store, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, key := range []string{"", "../escape", "/absolute", `dir\escape`} {
		if err := store.Put(ctx, key, bytes.NewReader(nil), 0, "application/octet-stream"); err == nil {
			t.Fatalf("unsafe key %q was accepted", key)
		}
	}
	if err := store.Put(ctx, "safe/object", bytes.NewReader([]byte("first")), 5, "text/plain"); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "safe/object", bytes.NewReader([]byte("second")), 6, "text/plain"); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Get(ctx, "safe/object")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content, _ := io.ReadAll(reader)
	if string(content) != "first" {
		t.Fatalf("immutable object was replaced: %q", content)
	}
}

func TestFSConcurrentPutHasOneImmutableWinner(t *testing.T) {
	store, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	values := [][]byte{[]byte("writer-one"), []byte("writer-two")}
	start := make(chan struct{})
	errors := make(chan error, len(values))
	var wait sync.WaitGroup
	for _, value := range values {
		value := value
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errors <- store.Put(ctx, "race/object", bytes.NewReader(value), int64(len(value)), "text/plain")
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	reader, err := store.Get(ctx, "race/object")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content, _ := io.ReadAll(reader)
	if !bytes.Equal(content, values[0]) && !bytes.Equal(content, values[1]) {
		t.Fatalf("unexpected winner content %q", content)
	}
}

func TestFSRejectsDeclaredSizeMismatch(t *testing.T) {
	store, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), "size/object", bytes.NewReader([]byte("data")), 3, "text/plain"); err == nil {
		t.Fatal("expected size mismatch")
	}
	if _, err := store.Stat(context.Background(), "size/object"); err != ErrNotFound {
		t.Fatalf("mismatched object was published: %v", err)
	}
}

func TestFSListPrefixIsBoundedSortedAndPrefixScoped(t *testing.T) {
	store, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for key, value := range map[string]string{
		"recordings/a/batches/0002":  "two",
		"recordings/a/batches/0001":  "one",
		"recordings/a/other":         "excluded",
		"recordings/ab/batches/0000": "wrong-prefix",
	} {
		if err := store.Put(ctx, key, bytes.NewReader([]byte(value)), int64(len(value)), "text/plain"); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.ListPrefix(ctx, "recordings/a/batches/", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Key != "recordings/a/batches/0001" || items[1].Key != "recordings/a/batches/0002" {
		t.Fatalf("unexpected prefix listing: %+v", items)
	}
	if items[0].LastModified.IsZero() || items[1].LastModified.IsZero() {
		t.Fatalf("listing omitted object modification time: %+v", items)
	}
	items, err = store.ListPrefix(ctx, "recordings/a/batches/", 1)
	if err != nil || len(items) != 1 {
		t.Fatalf("bounded listing failed: items=%+v err=%v", items, err)
	}
	for _, request := range []struct {
		prefix string
		limit  int
	}{{"recordings/a/batches", 1}, {"../", 1}, {"recordings/a/batches/", 0}} {
		if _, err := store.ListPrefix(ctx, request.prefix, request.limit); err == nil {
			t.Fatalf("invalid listing accepted: %+v", request)
		}
	}
}

func TestFSListPrefixRejectsSymlinks(t *testing.T) {
	store, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prefixRoot, err := store.path("prefix")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prefixRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(store.Root, "outside"), filepath.Join(prefixRoot, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListPrefix(context.Background(), "prefix/", 10); err == nil {
		t.Fatal("symlink below object prefix was accepted")
	}
}
