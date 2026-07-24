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
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/sdk/anchorplugin"
)

const (
	sinkName    = "example-go"
	proofSchema = "trustdb.example-go-anchor-proof.v1"
)

type examplePlugin struct {
	mu           sync.RWMutex
	blocks       map[string]anchorplugin.Resource
	transactions map[string]anchorplugin.Resource
}

type exampleProof struct {
	SchemaVersion string `json:"schema_version"`
	TreeSize      uint64 `json:"tree_size"`
	RootHash      []byte `json:"root_hash"`
}

func (*examplePlugin) Info(context.Context) (anchorplugin.Info, error) {
	return anchorplugin.Info{SinkName: sinkName, ProofSchema: proofSchema, System: &anchorplugin.System{
		SystemID:    "example-evidence-chain",
		DisplayName: "Example evidence blockchain",
		Kind:        anchorplugin.SystemKindEvidenceBlockchain,
		Network:     "example-local",
		Provider:    "trustdb-example",
		Capabilities: []string{
			anchorplugin.CapabilitySystemStatusRead,
			anchorplugin.CapabilityNodeRead,
			anchorplugin.CapabilityBlockRead,
			anchorplugin.CapabilityTransactionRead,
		},
		Assurance: anchorplugin.Assurance{Finality: "deterministic-demo", Custody: "operator"},
	}}, nil
}

func (p *examplePlugin) Publish(_ context.Context, sth anchorplugin.SignedTreeHead) (anchorplugin.AnchorResult, error) {
	proof, err := json.Marshal(exampleProof{
		SchemaVersion: proofSchema,
		TreeSize:      sth.TreeSize,
		RootHash:      append([]byte(nil), sth.RootHash...),
	})
	if err != nil {
		return anchorplugin.AnchorResult{}, anchorplugin.Permanent(err)
	}
	id := anchorID(sth)
	now := time.Now().UTC().UnixNano()
	p.mu.Lock()
	p.blocks[strconv.FormatUint(sth.TreeSize, 10)] = anchorplugin.Resource{
		Kind: anchorplugin.ResourceKindBlock, ResourceID: strconv.FormatUint(sth.TreeSize, 10), Hash: hex.EncodeToString(sth.RootHash), Height: sth.TreeSize,
		TimestampUnixN: now, Summary: fmt.Sprintf("block for TrustDB tree size %d", sth.TreeSize),
	}
	p.transactions[id] = anchorplugin.Resource{
		Kind: anchorplugin.ResourceKindTransaction, ResourceID: id, ParentID: strconv.FormatUint(sth.TreeSize, 10), Hash: id, Status: "committed",
		TimestampUnixN: now, Summary: "TrustDB STH anchor transaction", Attributes: map[string]string{"tree_size": strconv.FormatUint(sth.TreeSize, 10)},
	}
	p.mu.Unlock()
	return anchorplugin.AnchorResult{
		AnchorID:         id,
		Proof:            proof,
		PublishedAtUnixN: now,
	}, nil
}

func (*examplePlugin) Verify(_ context.Context, sth anchorplugin.SignedTreeHead, result anchorplugin.AnchorResult) error {
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

func (p *examplePlugin) Status(context.Context) (anchorplugin.SystemStatus, error) {
	p.mu.RLock()
	blocks := len(p.blocks)
	transactions := len(p.transactions)
	p.mu.RUnlock()
	return anchorplugin.SystemStatus{
		State: anchorplugin.SystemStateHealthy, ObservedAtUnixN: time.Now().UTC().UnixNano(), Message: "example provider is running",
		Details: map[string]string{"node_count": "1", "block_count": strconv.Itoa(blocks), "transaction_count": strconv.Itoa(transactions)},
	}, nil
}

func (p *examplePlugin) ListResources(_ context.Context, req anchorplugin.ListResourcesRequest) (anchorplugin.ListResourcesResponse, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var resources []anchorplugin.Resource
	switch req.Kind {
	case anchorplugin.ResourceKindNode:
		resources = []anchorplugin.Resource{{Kind: anchorplugin.ResourceKindNode, ResourceID: "example-node-1", Status: "online", Summary: "single demo validator"}}
	case anchorplugin.ResourceKindBlock:
		resources = mapResources(p.blocks)
	case anchorplugin.ResourceKindTransaction:
		resources = mapResources(p.transactions)
	default:
		return anchorplugin.ListResourcesResponse{}, anchorplugin.Permanent(fmt.Errorf("unsupported resource kind %q", req.Kind))
	}
	start := 0
	if req.Cursor != "" {
		parsed, err := strconv.Atoi(req.Cursor)
		if err != nil || parsed < 0 || parsed > len(resources) {
			return anchorplugin.ListResourcesResponse{}, anchorplugin.Permanent(fmt.Errorf("invalid resource cursor"))
		}
		start = parsed
	}
	end := min(start+req.Limit, len(resources))
	next := ""
	if end < len(resources) {
		next = strconv.Itoa(end)
	}
	return anchorplugin.ListResourcesResponse{Resources: resources[start:end], Limit: req.Limit, NextCursor: next}, nil
}

func (p *examplePlugin) Resource(_ context.Context, kind, resourceID string) (anchorplugin.Resource, bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	switch kind {
	case anchorplugin.ResourceKindNode:
		if resourceID == "example-node-1" {
			return anchorplugin.Resource{Kind: anchorplugin.ResourceKindNode, ResourceID: resourceID, Status: "online", Summary: "single demo validator"}, true, nil
		}
	case anchorplugin.ResourceKindBlock:
		resource, found := p.blocks[resourceID]
		return resource, found, nil
	case anchorplugin.ResourceKindTransaction:
		resource, found := p.transactions[resourceID]
		return resource, found, nil
	}
	return anchorplugin.Resource{}, false, nil
}

func mapResources(values map[string]anchorplugin.Resource) []anchorplugin.Resource {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	resources := make([]anchorplugin.Resource, 0, len(keys))
	for _, key := range keys {
		resources = append(resources, values[key])
	}
	return resources
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
	plugin := &examplePlugin{blocks: make(map[string]anchorplugin.Resource), transactions: make(map[string]anchorplugin.Resource)}
	if err := anchorplugin.Serve(context.Background(), plugin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
