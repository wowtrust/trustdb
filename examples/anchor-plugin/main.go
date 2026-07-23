// Command anchor-plugin is a minimal external L5 provider used to demonstrate
// the public Go SDK. It writes no independent external timestamp and therefore
// must not be treated as a production trust anchor.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/wowtrust/trustdb/sdk/anchorplugin"
)

const (
	sinkName    = "example-go"
	proofSchema = "trustdb.example-go-anchor-proof.v1"
)

type examplePlugin struct{}

type exampleProof struct {
	SchemaVersion string `json:"schema_version"`
	TreeSize      uint64 `json:"tree_size"`
	RootHash      []byte `json:"root_hash"`
}

func (examplePlugin) Info(context.Context) (anchorplugin.Info, error) {
	return anchorplugin.Info{SinkName: sinkName, ProofSchema: proofSchema}, nil
}

func (examplePlugin) Publish(_ context.Context, sth anchorplugin.SignedTreeHead) (anchorplugin.AnchorResult, error) {
	proof, err := json.Marshal(exampleProof{
		SchemaVersion: proofSchema,
		TreeSize:      sth.TreeSize,
		RootHash:      append([]byte(nil), sth.RootHash...),
	})
	if err != nil {
		return anchorplugin.AnchorResult{}, anchorplugin.Permanent(err)
	}
	return anchorplugin.AnchorResult{
		AnchorID:         anchorID(sth),
		Proof:            proof,
		PublishedAtUnixN: time.Now().UTC().UnixNano(),
	}, nil
}

func (examplePlugin) Verify(_ context.Context, sth anchorplugin.SignedTreeHead, result anchorplugin.AnchorResult) error {
	if result.AnchorID != anchorID(sth) {
		return anchorplugin.Permanent(fmt.Errorf("anchor_id mismatch"))
	}
	var proof exampleProof
	if err := json.Unmarshal(result.Proof, &proof); err != nil {
		return anchorplugin.Permanent(fmt.Errorf("decode proof: %w", err))
	}
	if proof.SchemaVersion != proofSchema || proof.TreeSize != sth.TreeSize || !bytes.Equal(proof.RootHash, sth.RootHash) {
		return anchorplugin.Permanent(fmt.Errorf("proof does not bind the supplied signed tree head"))
	}
	return nil
}

func anchorID(sth anchorplugin.SignedTreeHead) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(proofSchema))
	var treeSize [8]byte
	binary.BigEndian.PutUint64(treeSize[:], sth.TreeSize)
	_, _ = hash.Write(treeSize[:])
	_, _ = hash.Write(sth.RootHash)
	return hex.EncodeToString(hash.Sum(nil))
}

func main() {
	if err := anchorplugin.Serve(context.Background(), examplePlugin{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
