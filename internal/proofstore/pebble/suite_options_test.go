package pebble

import "github.com/wowtrust/trustdb/v2/internal/cryptosuite"
import "github.com/wowtrust/trustdb/v2/internal/proofstoremeta"

func testStoreOptions(opts Options) Options {
	if opts.CryptoSuite == "" {
		opts.CryptoSuite = cryptosuite.INTLV1
	}
	if opts.NodeID == "" {
		opts.NodeID = "test-node"
	}
	if opts.LogID == "" {
		opts.LogID = "test-log"
	}
	if opts.NamespaceID == "" {
		opts.NamespaceID = "test-pebble"
	}
	return opts
}

func testStoreBinding() proofstoremeta.Marker {
	binding, err := proofstoremeta.New(cryptosuite.INTLV1, "test-node", "test-log", "test-pebble")
	if err != nil {
		panic(err)
	}
	return binding
}
