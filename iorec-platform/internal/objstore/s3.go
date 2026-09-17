package objstore

import (
	"context"
	"errors"
	"io"
	"net/url"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 is an S3-compatible backend (AWS S3, MinIO, GCS interop, ...).
type S3 struct {
	client *minio.Client
	bucket string
}

// S3Config configures the backend.
type S3Config struct {
	Endpoint  string // e.g. http://minio:9000 or https://s3.amazonaws.com
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
}

// NewS3 connects and ensures the bucket exists.
func NewS3(ctx context.Context, c S3Config) (*S3, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, err
	}
	cl, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(c.AccessKey, c.SecretKey, ""),
		Secure: u.Scheme == "https",
		Region: c.Region,
	})
	if err != nil {
		return nil, err
	}
	exists, err := cl.BucketExists(ctx, c.Bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := cl.MakeBucket(ctx, c.Bucket, minio.MakeBucketOptions{Region: c.Region}); err != nil {
			return nil, err
		}
	}
	return &S3{client: cl, bucket: c.Bucket}, nil
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	if _, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{}); err == nil {
		return nil // immutable
	}
	options := minio.PutObjectOptions{ContentType: contentType, DisableMultipart: true}
	options.SetMatchETagExcept("*")
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, options)
	if err != nil {
		response := minio.ToErrorResponse(err)
		if response.Code == "PreconditionFailed" || response.Code == "ConditionalRequestConflict" {
			return nil // a concurrent immutable writer won
		}
	}
	return err
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := obj.Stat(); err != nil {
		var mErr minio.ErrorResponse
		if errors.As(err, &mErr) && mErr.Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return obj, nil
}

func (s *S3) Stat(ctx context.Context, key string) (int64, error) {
	st, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		var mErr minio.ErrorResponse
		if errors.As(err, &mErr) && mErr.Code == "NoSuchKey" {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return st.Size, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

// ListPrefix returns at most limit objects in lexical key order.
func (s *S3) ListPrefix(ctx context.Context, prefix string, limit int) ([]ListedObject, error) {
	if limit < 1 || limit > 100_001 || prefix == "" {
		return nil, errors.New("objstore: invalid list request")
	}
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	items := make([]ListedObject, 0)
	for object := range s.client.ListObjects(listCtx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true, MaxKeys: limit}) {
		if object.Err != nil {
			return nil, object.Err
		}
		items = append(items, ListedObject{Key: object.Key, LastModified: object.LastModified.UTC()})
		if len(items) >= limit {
			cancel()
			break
		}
	}
	return items, nil
}
