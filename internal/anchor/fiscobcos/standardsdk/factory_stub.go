//go:build !fiscobcos_sdk || !cgo

package standardsdk

import (
	"context"
	"fmt"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
)

func (NativeFactory) NewDrivers(context.Context, Config) ([]fiscobcos.Driver, error) {
	return nil, fmt.Errorf("%w; rebuild with CGO_ENABLED=1 and -tags=fiscobcos_sdk against the pinned native C SDK", ErrSDKNotBuilt)
}
