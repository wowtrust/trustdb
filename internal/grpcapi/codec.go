package grpcapi

import (
	"github.com/wowtrust/trustdb/internal/cborx"
	"google.golang.org/grpc/encoding"
)

const CodecName = "trustdb-cbor"

func init() {
	encoding.RegisterCodec(cborCodec{})
}

func Codec() encoding.Codec {
	return cborCodec{}
}

type cborCodec struct{}

func (cborCodec) Marshal(v any) ([]byte, error) {
	return cborx.Marshal(v)
}

func (cborCodec) Unmarshal(data []byte, v any) error {
	return cborx.UnmarshalLimit(data, v, MaxMessageBytes)
}

func (cborCodec) Name() string {
	return CodecName
}
