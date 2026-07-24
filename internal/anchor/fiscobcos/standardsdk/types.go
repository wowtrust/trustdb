// Package standardsdk isolates the pinned FISCO BCOS Go SDK from TrustDB's
// scheduler, proof model, configuration, and portable build graph.
package standardsdk

import (
	"context"
	"errors"
	"time"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
)

var ErrSDKNotBuilt = errors.New("FISCO BCOS standard SDK support is not present in this build")

// AccountSigner exposes only a non-exportable standard-chain signing
// capability. SignDigest must return the canonical 65-byte secp256k1
// signature expected by FISCO BCOS. Private key bytes are never requested.
type AccountSigner interface {
	PublicKey(context.Context) ([]byte, error)
	SignDigest(context.Context, []byte) ([]byte, error)
}

type Config struct {
	TrustConfig   fiscobcos.TrustConfig
	AccountSigner AccountSigner
	Clock         func() time.Time
}

type Factory interface {
	NewDrivers(context.Context, Config) ([]fiscobcos.Driver, error)
}

type NativeFactory struct{}
