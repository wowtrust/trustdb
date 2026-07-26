package sdk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestReaderClaimBuildersObserveCancellationDuringHashing(t *testing.T) {
	t.Parallel()

	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	identity := mustINTLV1Identity(t, "tenant-1", "client-1", "key-1", privateKey)

	tests := []struct {
		name  string
		build func(context.Context, io.Reader) error
	}{
		{
			name: "file",
			build: func(ctx context.Context, reader io.Reader) error {
				_, err := BuildSignedFileClaimContext(ctx, reader, identity, FileClaimOptions{})
				return err
			},
		},
		{
			name: "log",
			build: func(ctx context.Context, reader io.Reader) error {
				_, err := BuildSignedLogClaimContext(ctx, reader, identity, LogClaimOptions{})
				return err
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			reader := &cancelAfterFirstRead{
				reader: bytes.NewReader(bytes.Repeat([]byte("x"), 128<<10)),
				cancel: cancel,
			}
			err := test.build(ctx, reader)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("build error = %v, want context.Canceled", err)
			}
			if reader.reads != 1 {
				t.Fatalf("underlying reads = %d, want 1", reader.reads)
			}
		})
	}
}

type cancelAfterFirstRead struct {
	reader io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *cancelAfterFirstRead) Read(buffer []byte) (int, error) {
	r.reads++
	n, err := r.reader.Read(buffer)
	if r.reads == 1 {
		r.cancel()
	}
	return n, err
}
