package site

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// Storage is the site's bucket. Documents are written once; the index is
// replaced only over the version read.
type Storage interface {
	// Get returns an object and its version tag, or ErrNotExist.
	Get(ctx context.Context, path string) (data []byte, tag string, err error)
	// PutOnce writes an object only if nothing is at path (ErrExists
	// otherwise).
	PutOnce(ctx context.Context, path string, data []byte, contentType string) error
	// PutIf replaces an object only if its tag is still tag ("" for an
	// object that doesn't exist yet); ErrChanged otherwise.
	PutIf(ctx context.Context, path string, data []byte, contentType, tag string) error
}

// Storage errors.
var (
	ErrNotExist = errors.New("site: no such object")
	ErrExists   = errors.New("site: object exists")
	ErrChanged  = errors.New("site: object changed")
)

// MemStorage is an in-memory Storage, for tests.
type MemStorage struct {
	mu      sync.Mutex
	Objects map[string][]byte
}

func tagOf(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:8]) }

// Get implements Storage.
func (m *MemStorage) Get(_ context.Context, path string) ([]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.Objects[path]
	if !ok {
		return nil, "", ErrNotExist
	}
	return bytes.Clone(b), tagOf(b), nil
}

// PutOnce implements Storage.
func (m *MemStorage) PutOnce(_ context.Context, path string, data []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Objects == nil {
		m.Objects = map[string][]byte{}
	}
	if _, ok := m.Objects[path]; ok {
		return ErrExists
	}
	m.Objects[path] = bytes.Clone(data)
	return nil
}

// PutIf implements Storage.
func (m *MemStorage) PutIf(_ context.Context, path string, data []byte, _, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Objects == nil {
		m.Objects = map[string][]byte{}
	}
	cur, ok := m.Objects[path]
	if (tag == "" && ok) || (tag != "" && (!ok || tagOf(cur) != tag)) {
		return ErrChanged
	}
	m.Objects[path] = bytes.Clone(data)
	return nil
}
