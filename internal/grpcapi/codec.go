package grpcapi

import (
	"github.com/wowtrust/trustdb/v2/internal/cborx"
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
	return cborx.UnmarshalLimits(data, v, MaxMessageBytes, MaxCBORArrayElements, MaxCBORMapPairs)
}

func (cborCodec) Name() string {
	return CodecName
}
