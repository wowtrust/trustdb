package cborx

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

const (
	DefaultMaxBytes        = 1 << 20
	defaultMaxNestedLevels = 16
	defaultMaxArrayElems   = 1 << 20
	defaultMaxMapPairs     = 1 << 16
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.TagsMd = cbor.TagsForbidden
	encOpts.IndefLength = cbor.IndefLengthForbidden

	var err error
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("trustdb cbor enc mode: %v", err))
	}

	decOpts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   defaultMaxNestedLevels,
		MaxArrayElements:  defaultMaxArrayElems,
		MaxMapPairs:       defaultMaxMapPairs,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		NaN:               cbor.NaNDecodeForbidden,
		Inf:               cbor.InfDecodeForbidden,
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("trustdb cbor dec mode: %v", err))
	}
}

func Marshal(v any) ([]byte, error) {
	if v == nil {
		return nil, errors.New("cborx: cannot marshal nil")
	}
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cborx: marshal: %w", err)
	}
	return b, nil
}

func MarshalBuffer(buf *bytes.Buffer, v any) error {
	if v == nil {
		return errors.New("cborx: cannot marshal nil")
	}
	if buf == nil {
		return errors.New("cborx: nil buffer")
	}
	before := buf.Len()
	if err := encMode.NewEncoder(buf).Encode(v); err != nil {
		buf.Truncate(before)
		return fmt.Errorf("cborx: marshal: %w", err)
	}
	return nil
}

func Unmarshal(data []byte, v any) error {
	return UnmarshalLimit(data, v, DefaultMaxBytes)
}

func UnmarshalLimit(data []byte, v any, maxBytes int) error {
	if maxBytes <= 0 {
		return errors.New("cborx: max bytes must be positive")
	}
	if len(data) > maxBytes {
		return fmt.Errorf("cborx: payload too large: %d > %d", len(data), maxBytes)
	}
	if len(data) == 0 {
		return errors.New("cborx: empty payload")
	}
	if err := decMode.Unmarshal(data, v); err != nil {
		return fmt.Errorf("cborx: unmarshal: %w", err)
	}
	return nil
}

func DecodeReaderLimit(r io.Reader, v any, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("cborx: max bytes must be positive")
	}
	if r == nil {
		return errors.New("cborx: nil reader")
	}
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	counting := &readerCounter{r: limited}
	decoder := decMode.NewDecoder(counting)
	if err := decoder.Decode(v); err != nil {
		if counting.n > maxBytes {
			return fmt.Errorf("cborx: payload too large: %d > %d", counting.n, maxBytes)
		}
		return fmt.Errorf("cborx: decode: %w", err)
	}
	if int64(decoder.NumBytesRead()) > maxBytes {
		return fmt.Errorf("cborx: payload too large: %d > %d", decoder.NumBytesRead(), maxBytes)
	}
	if ok, err := readOne(decoder.Buffered()); err != nil {
		return fmt.Errorf("cborx: read buffered trailing data: %w", err)
	} else if ok {
		return errors.New("cborx: trailing data")
	}
	if ok, err := readOne(counting); err != nil {
		return fmt.Errorf("cborx: read trailing data: %w", err)
	} else if ok {
		return errors.New("cborx: trailing data")
	}
	return nil
}

func Wellformed(data []byte) error {
	if len(data) > DefaultMaxBytes {
		return fmt.Errorf("cborx: payload too large: %d > %d", len(data), DefaultMaxBytes)
	}
	if err := decMode.Wellformed(data); err != nil {
		return fmt.Errorf("cborx: wellformed: %w", err)
	}
	return nil
}

type readerCounter struct {
	r io.Reader
	n int64
}

func (r *readerCounter) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func readOne(r io.Reader) (bool, error) {
	var b [1]byte
	n, err := r.Read(b[:])
	if n > 0 {
		return true, nil
	}
	if err == io.EOF {
		return false, nil
	}
	return false, err
}
