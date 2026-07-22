package objectstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/wowtrust/trustdb/internal/model"
)

const copyBufferSize = 256 * 1024

var copyBufferPool = sync.Pool{New: func() any { return new([copyBufferSize]byte) }}

type LocalStore struct {
	Root string
}

type PutResult struct {
	HashAlg       string
	ContentHash   []byte
	ContentLength int64
	URI           string
	Path          string
}

func (s LocalStore) PutFile(ctx context.Context, path string) (PutResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return PutResult{}, err
	}
	defer f.Close()
	return s.Put(ctx, f)
}

func (s LocalStore) Put(ctx context.Context, r io.Reader) (PutResult, error) {
	if s.Root == "" {
		return PutResult{}, fmt.Errorf("objectstore: root is required")
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return PutResult{}, err
	}
	tmp, err := os.CreateTemp(s.Root, "put-*.tmp")
	if err != nil {
		return PutResult{}, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	h := sha256.New()
	n, err := copyWithContext(ctx, io.MultiWriter(tmp, h), r)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return PutResult{}, err
	}
	sum := h.Sum(nil)
	hexSum := hex.EncodeToString(sum)
	finalPath := s.pathForHex(hexSum)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return PutResult{}, err
	}
	if info, err := os.Stat(finalPath); err == nil {
		if info.IsDir() {
			return PutResult{}, fmt.Errorf("objectstore: object path %s is a directory", finalPath)
		}
		return PutResult{
			HashAlg:       model.DefaultHashAlg,
			ContentHash:   sum,
			ContentLength: n,
			URI:           "trustdb-local://" + model.DefaultHashAlg + "/" + hexSum,
			Path:          finalPath,
		}, nil
	} else if !os.IsNotExist(err) {
		return PutResult{}, err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return PutResult{}, err
	}
	return PutResult{
		HashAlg:       model.DefaultHashAlg,
		ContentHash:   sum,
		ContentLength: n,
		URI:           "trustdb-local://" + model.DefaultHashAlg + "/" + hexSum,
		Path:          finalPath,
	}, nil
}

func (s LocalStore) Open(hash []byte) (*os.File, error) {
	if len(hash) != sha256.Size {
		return nil, fmt.Errorf("objectstore: invalid sha256 size: %d", len(hash))
	}
	return os.Open(s.pathForHex(hex.EncodeToString(hash)))
}

func (s LocalStore) pathForHex(hexSum string) string {
	return filepath.Join(s.Root, model.DefaultHashAlg, hexSum[:2], hexSum[2:4], hexSum)
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := copyBufferPool.Get().(*[copyBufferSize]byte)
	defer copyBufferPool.Put(buf)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		nr, er := src.Read(buf[:])
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nw > nr {
				return written, io.ErrShortWrite
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}
