//go:build !fiscobcos_sdk || !cgo

package standardsdk

import (
	"context"
	"errors"
	"testing"
)

func TestPortableFactoryFailsClosedWithoutNativeSDK(t *testing.T) {
	t.Parallel()
	drivers, err := (NativeFactory{}).NewDrivers(context.Background(), Config{})
	if !errors.Is(err, ErrSDKNotBuilt) || drivers != nil {
		t.Fatalf("NewDrivers() drivers=%v error=%v, want ErrSDKNotBuilt", drivers, err)
	}
}
