// Package objstore abstracts the immutable object store (S3-compatible or local filesystem).
package objstore

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned by Get/Stat for missing keys.
var ErrNotFound = errors.New("objstore: not found")

// Store is an append-only key/value blob store.
type Store interface {
	// Put writes the object. If the key exists with identical content it is a no-op.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Stat(ctx context.Context, key string) (int64, error)
	Delete(ctx context.Context, key string) error
}

// ListedObject is the bounded metadata needed for orphan discovery.
type ListedObject struct {
	Key          string
	LastModified time.Time
}

// PrefixLister is implemented by production stores. It is separate from Store
// so focused test doubles used by unrelated pipeline tests remain small.
type PrefixLister interface {
	ListPrefix(ctx context.Context, prefix string, limit int) ([]ListedObject, error)
}
