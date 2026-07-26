package proofstore

import "github.com/wowtrust/trustdb/v2/internal/cryptosuite"

func testStoreConfig(cfg Config) Config {
	if cfg.Kind == "" {
		cfg.Kind = BackendFile
	}
	if cfg.CryptoSuite == "" {
		cfg.CryptoSuite = cryptosuite.INTLV1
	}
	if cfg.NodeID == "" {
		cfg.NodeID = "test-node"
	}
	if cfg.LogID == "" {
		cfg.LogID = "test-log"
	}
	if cfg.NamespaceID == "" {
		cfg.NamespaceID = "test-file"
	}
	return cfg
}
