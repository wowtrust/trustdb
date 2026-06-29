package cborx

import (
	"bytes"
	"strings"
	"testing"
)

type sample struct {
	A string `cbor:"a"`
	B int    `cbor:"b"`
}

func TestMarshalDeterministic(t *testing.T) {
	t.Parallel()

	v := sample{A: "x", B: 7}
	first, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	second, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal() second error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("Marshal() not deterministic:\nfirst=%x\nsecond=%x", first, second)
	}
}

func TestMarshalBufferMatchesMarshal(t *testing.T) {
	t.Parallel()

	v := sample{A: "x", B: 7}
	want, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var buf bytes.Buffer
	if err := MarshalBuffer(&buf, v); err != nil {
		t.Fatalf("MarshalBuffer() error = %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("MarshalBuffer() = %x, want %x", buf.Bytes(), want)
	}
}

func TestUnmarshalRejectsDuplicateMapKeys(t *testing.T) {
	t.Parallel()

	dup := []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}
	var got map[string]int
	if err := Unmarshal(dup, &got); err == nil {
		t.Fatal("Unmarshal() error = nil, want duplicate map key error")
	}
}

func TestUnmarshalRejectsIndefiniteLength(t *testing.T) {
	t.Parallel()

	indefiniteText := []byte{0x7f, 0x61, 0x61, 0xff}
	var got string
	if err := Unmarshal(indefiniteText, &got); err == nil {
		t.Fatal("Unmarshal() error = nil, want indefinite length error")
	}
}

func TestUnmarshalLimit(t *testing.T) {
	t.Parallel()

	data, err := Marshal(sample{A: "x", B: 7})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got sample
	if err := UnmarshalLimit(data, &got, len(data)-1); err == nil {
		t.Fatal("UnmarshalLimit() error = nil, want size error")
	}
}

func TestDecodeReaderLimitRejectsTrailingData(t *testing.T) {
	t.Parallel()

	data, err := Marshal(sample{A: "x", B: 7})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	data = append(data, 0xf6) // valid second CBOR item (null)
	var got sample
	err = DecodeReaderLimit(bytes.NewReader(data), &got, int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("DecodeReaderLimit() error = %v, want trailing data", err)
	}
}

func TestDecodeReaderLimitRejectsOversizedSingleItem(t *testing.T) {
	t.Parallel()

	data, err := Marshal(sample{A: "x", B: 7})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got sample
	err = DecodeReaderLimit(bytes.NewReader(data), &got, int64(len(data)-1))
	if err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("DecodeReaderLimit() error = %v, want payload too large", err)
	}
}
