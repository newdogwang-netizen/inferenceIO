package objstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FS stores objects under a root directory. Used for dev and tests.
type FS struct{ Root string }

// NewFS creates the root if needed.
func NewFS(root string) (*FS, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return nil, err
	}
	return &FS{Root: realRoot}, nil
}

func (f *FS) path(key string) (string, error) {
	if key == "" || strings.Contains(key, "\\") {
		return "", errors.New("objstore: invalid key")
	}
	clean := filepath.Clean(filepath.FromSlash(key))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("objstore: invalid key")
	}
	return filepath.Join(f.Root, clean), nil
}

func (f *FS) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil // immutable: existing object wins
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	written, err := io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		return err
	}
	if written != size {
		tmp.Close()
		return errors.New("objstore: object size does not match declaration")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), p); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	dir, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (f *FS) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	p, err := f.path(key)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(p)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return fh, err
}

func (f *FS) Stat(ctx context.Context, key string) (int64, error) {
	p, err := f.path(key)
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(p)
	if os.IsNotExist(err) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func (f *FS) Delete(ctx context.Context, key string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ListPrefix returns at most limit regular objects below a key prefix.
func (f *FS) ListPrefix(ctx context.Context, prefix string, limit int) ([]ListedObject, error) {
	if limit < 1 || limit > 100_001 || !strings.HasSuffix(prefix, "/") {
		return nil, errors.New("objstore: invalid list request")
	}
	root, err := f.path(strings.TrimSuffix(prefix, "/"))
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return []ListedObject{}, nil
	} else if err != nil {
		return nil, err
	}
	items := make([]ListedObject, 0)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return errors.New("objstore: symlink found below object prefix")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("objstore: non-regular object found below prefix")
		}
		relative, err := filepath.Rel(f.Root, path)
		if err != nil {
			return err
		}
		items = append(items, ListedObject{Key: filepath.ToSlash(relative), LastModified: info.ModTime().UTC()})
		if len(items) >= limit {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items, nil
}
