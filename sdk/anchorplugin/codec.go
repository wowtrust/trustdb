package anchorplugin

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc/encoding"
)

const CodecName = "trustdb-anchor-plugin-cbor"

var (
	encMode = mustEncMode()
	decMode = mustDecMode()
)

func init() {
	encoding.RegisterCodec(cborCodec{})
}

func Codec() encoding.Codec { return cborCodec{} }

type cborCodec struct{}

func (cborCodec) Marshal(v any) ([]byte, error) { return encMode.Marshal(v) }

func (cborCodec) Unmarshal(data []byte, v any) error {
	if len(data) > MaxMessageBytes {
		return fmt.Errorf("anchor plugin message exceeds %d bytes", MaxMessageBytes)
	}
	return decMode.Unmarshal(data, v)
}

func (cborCodec) Name() string { return CodecName }

func mustEncMode() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func mustDecMode() cbor.DecMode {
	opts := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		MaxNestedLevels:   32,
		MaxArrayElements:  1 << 20,
		MaxMapPairs:       1 << 20,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	mode, err := opts.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}
