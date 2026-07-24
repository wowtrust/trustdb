package signerplugin

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc/encoding"
)

const CodecName = "trustdb-signer-plugin-cbor"

var (
	encMode = mustEncMode()
	decMode = mustDecMode()
	// grpc-go rewrites codec decode errors to codes.Internal and drops the
	// original error identity.  RPC clients register their response pointer
	// here for the duration of Invoke so malformed wire responses remain
	// distinguishable from a provider's application-level Internal error.
	trackedDecodes sync.Map
)

type decodeFailureTracker struct {
	failed atomic.Bool
}

func init() {
	encoding.RegisterCodec(cborCodec{})
}

func Codec() encoding.Codec { return cborCodec{} }

type cborCodec struct{}

func (cborCodec) Marshal(value any) ([]byte, error) {
	data, err := encMode.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("signer plugin message exceeds %d bytes", MaxMessageBytes)
	}
	return data, nil
}

func (cborCodec) Unmarshal(data []byte, value any) (err error) {
	defer func() {
		if err != nil {
			markTrackedDecodeFailure(value)
		}
	}()
	if len(data) > MaxMessageBytes {
		return fmt.Errorf("signer plugin message exceeds %d bytes", MaxMessageBytes)
	}
	if err := decMode.Unmarshal(data, value); err != nil {
		return err
	}
	canonical, err := encMode.Marshal(value)
	if err != nil {
		return fmt.Errorf("re-encode signer plugin message: %w", err)
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("signer plugin message is not canonical CBOR")
	}
	return nil
}

func (cborCodec) Name() string { return CodecName }

func trackDecodeFailure(value any) *decodeFailureTracker {
	tracker := &decodeFailureTracker{}
	trackedDecodes.Store(value, tracker)
	return tracker
}

func finishDecodeFailureTracking(value any, tracker *decodeFailureTracker) bool {
	trackedDecodes.Delete(value)
	return tracker.failed.Load()
}

func markTrackedDecodeFailure(value any) {
	if value == nil || !reflect.TypeOf(value).Comparable() {
		return
	}
	tracked, ok := trackedDecodes.Load(value)
	if !ok {
		return
	}
	tracked.(*decodeFailureTracker).failed.Store(true)
}

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
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   16,
		MaxArrayElements:  64,
		MaxMapPairs:       64,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
	}
	mode, err := opts.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}
