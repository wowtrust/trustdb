package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

type exportEvidenceTransport struct {
	Transport
	bundle        ProofBundle
	evidence      GlobalLogEvidence
	bundleCalls   atomic.Int32
	evidenceCalls atomic.Int32
}

func (t *exportEvidenceTransport) GetProofBundle(context.Context, string) (ProofBundle, error) {
	t.bundleCalls.Add(1)
	return t.bundle, nil
}

func (t *exportEvidenceTransport) GetGlobalEvidence(context.Context, string) (GlobalLogEvidence, error) {
	t.evidenceCalls.Add(1)
	return t.evidence, nil
}

func TestClientSubmitSignedClaim(t *testing.T) {
	t.Parallel()

	signed := SignedClaim{
		SchemaVersion: model.SchemaSignedClaim,
		Claim: model.ClientClaim{
			SchemaVersion:  model.SchemaClientClaim,
			TenantID:       "tenant-1",
			ClientID:       "client-1",
			KeyID:          "key-1",
			IdempotencyKey: "idem-1",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/claims" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/cbor" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "trustdb-go-sdk" {
			t.Fatalf("User-Agent = %q", got)
		}
		var decoded SignedClaim
		if err := cborx.DecodeReaderLimit(r.Body, &decoded, 1<<20); err != nil {
			t.Fatalf("DecodeReaderLimit: %v", err)
		}
		if decoded.Claim.IdempotencyKey != "idem-1" {
			t.Fatalf("decoded claim = %+v", decoded.Claim)
		}
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID:      "tr1record",
			Status:        "accepted",
			ProofLevel:    ProofLevelL2,
			BatchEnqueued: true,
			ServerRecord: ServerRecord{
				SchemaVersion: model.SchemaServerRecord,
				RecordID:      "tr1record",
			},
			AcceptedReceipt: AcceptedReceipt{
				SchemaVersion: model.SchemaAcceptedReceipt,
				RecordID:      "tr1record",
				Status:        "accepted",
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.SubmitSignedClaim(context.Background(), signed)
	if err != nil {
		t.Fatalf("SubmitSignedClaim: %v", err)
	}
	if result.RecordID != "tr1record" || result.ProofLevel != ProofLevelL2 || !result.BatchEnqueued {
		t.Fatalf("result = %+v", result)
	}
}

func TestLoadBalancedClientFailsOver(t *testing.T) {
	t.Parallel()

	var primaryHits atomic.Int64
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/claims" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID:      "tr1record",
			Status:        "accepted",
			ProofLevel:    ProofLevelL2,
			BatchEnqueued: true,
			ServerRecord: ServerRecord{
				SchemaVersion: model.SchemaServerRecord,
				RecordID:      "tr1record",
			},
			AcceptedReceipt: AcceptedReceipt{
				SchemaVersion: model.SchemaAcceptedReceipt,
				RecordID:      "tr1record",
				Status:        "accepted",
			},
		})
	}))
	defer secondary.Close()

	client, err := NewLoadBalancedClient(
		[]string{primary.URL, secondary.URL},
		LoadBalanceOptions{Mode: LoadBalanceFailover},
	)
	if err != nil {
		t.Fatalf("NewLoadBalancedClient: %v", err)
	}
	result, err := client.SubmitSignedClaim(context.Background(), SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("SubmitSignedClaim: %v", err)
	}
	if result.RecordID != "tr1record" {
		t.Fatalf("result = %+v", result)
	}
	if primaryHits.Load() == 0 {
		t.Fatal("primary endpoint was not attempted")
	}
}

func TestLoadBalancedClientNilContextDoesNotPanic(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/claims" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSONForTest(t, w, http.StatusAccepted, submitClaimEnvelope{
			RecordID:   "tr1record",
			Status:     "accepted",
			ProofLevel: ProofLevelL2,
			ServerRecord: ServerRecord{
				SchemaVersion: model.SchemaServerRecord,
				RecordID:      "tr1record",
			},
			AcceptedReceipt: AcceptedReceipt{
				SchemaVersion: model.SchemaAcceptedReceipt,
				RecordID:      "tr1record",
				Status:        "accepted",
			},
		})
	}))
	defer server.Close()

	client, err := NewLoadBalancedClient([]string{server.URL}, LoadBalanceOptions{Mode: LoadBalanceFailover})
	if err != nil {
		t.Fatalf("NewLoadBalancedClient: %v", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("SubmitSignedClaim(nil) panicked: %v", recovered)
		}
	}()
	result, err := client.SubmitSignedClaim(nil, SignedClaim{SchemaVersion: model.SchemaSignedClaim})
	if err != nil {
		t.Fatalf("SubmitSignedClaim: %v", err)
	}
	if result.RecordID != "tr1record" {
		t.Fatalf("result = %+v", result)
	}
}

func TestClientListRecordsEncodesQuery(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/records" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("limit") != "25" ||
			query.Get("direction") != "asc" ||
			query.Get("batch_id") != "batch-1" ||
			query.Get("level") != "L4" ||
			query.Get("q") != "hello" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		writeJSONForTest(t, w, http.StatusOK, recordsEnvelope{
			Records: []RecordIndex{{
				SchemaVersion: model.SchemaRecordIndex,
				RecordID:      "tr1record",
				BatchID:       "batch-1",
			}},
			Limit:      25,
			Direction:  "asc",
			NextCursor: "next",
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	page, err := client.ListRecords(context.Background(), ListRecordsOptions{
		Limit:      25,
		Direction:  RecordListDirectionAsc,
		BatchID:    "batch-1",
		ProofLevel: "L4",
		Query:      "hello",
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(page.Records) != 1 || page.NextCursor != "next" {
		t.Fatalf("page = %+v", page)
	}
}

func TestClientOperationalEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			writeJSONForTest(t, w, http.StatusOK, map[string]bool{"ok": true})
		case "/v1/roots":
			if r.URL.Query().Get("limit") != "7" || r.URL.Query().Get("direction") != "desc" {
				t.Fatalf("roots query = %s", r.URL.RawQuery)
			}
			writeJSONForTest(t, w, http.StatusOK, rootsEnvelope{Roots: []BatchRoot{{
				SchemaVersion: model.SchemaBatchRoot,
				BatchID:       "batch-1",
				TreeSize:      1,
			}}, Limit: 7, Direction: "desc", NextCursor: "root-next"})
		case "/v1/sth":
			writeJSONForTest(t, w, http.StatusOK, sthsEnvelope{
				STHs:  []SignedTreeHead{{SchemaVersion: model.SchemaSignedTreeHead, TreeSize: 4, RootHash: []byte{4}}},
				Limit: 5, Direction: "desc", NextCursor: "sth-next",
			})
		case "/v1/global-log/leaves":
			writeJSONForTest(t, w, http.StatusOK, globalLeavesEnvelope{
				Leaves: []model.GlobalLogLeaf{{SchemaVersion: model.SchemaGlobalLogLeaf, BatchID: "batch-1", LeafIndex: 3}},
				Limit:  5, Direction: "desc", NextCursor: "leaf-next",
			})
		case "/v1/anchors/sth":
			writeJSONForTest(t, w, http.StatusOK, anchorsEnvelope{
				Anchors: []anchorEnvelope{{
					TreeSize:   4,
					Status:     model.AnchorStatePublished,
					ProofLevel: ProofLevelL5,
					Result:     &STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 4, AnchorID: "anchor-4"},
				}},
				Limit: 5, Direction: "desc", NextCursor: "anchor-next",
			})
		case "/v1/anchors/sth/4":
			writeJSONForTest(t, w, http.StatusOK, anchorEnvelope{
				TreeSize:   4,
				Status:     model.AnchorStatePublished,
				ProofLevel: ProofLevelL5,
				Result:     &STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 4, AnchorID: "anchor-4"},
			})
		case "/v1/anchor-systems":
			writeJSONForTest(t, w, http.StatusOK, map[string]any{"systems": []model.AnchorSystem{sdkHTTPTestAnchorSystem()}})
		case "/v1/anchor-systems/chain-a":
			writeJSONForTest(t, w, http.StatusOK, sdkHTTPTestAnchorSystem())
		case "/v1/anchor-systems/chain-a/status":
			writeJSONForTest(t, w, http.StatusOK, model.AnchorSystemStatus{SchemaVersion: model.SchemaAnchorSystemStatus, SystemID: "chain-a", State: model.AnchorSystemStateHealthy, ObservedAtUnixN: 1})
		case "/v1/anchor-systems/chain-a/resources":
			if r.URL.Query().Get("kind") != model.AnchorResourceKindNode || r.URL.Query().Get("limit") != "5" {
				t.Fatalf("anchor resources query = %s", r.URL.RawQuery)
			}
			writeJSONForTest(t, w, http.StatusOK, model.AnchorSystemResourcePage{Resources: []model.AnchorSystemResource{{SchemaVersion: model.SchemaAnchorSystemResource, SystemID: "chain-a", Kind: model.AnchorResourceKindNode, ResourceID: "node-1", Status: "online"}}, Limit: 5})
		case "/v1/anchor-systems/chain-a/resources/node/node-1":
			writeJSONForTest(t, w, http.StatusOK, model.AnchorSystemResource{SchemaVersion: model.SchemaAnchorSystemResource, SystemID: "chain-a", Kind: model.AnchorResourceKindNode, ResourceID: "node-1", Status: "online"})
		case "/v1/roots/latest":
			writeJSONForTest(t, w, http.StatusOK, BatchRoot{
				SchemaVersion: model.SchemaBatchRoot,
				BatchID:       "batch-latest",
				TreeSize:      2,
			})
		case "/metrics":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("trustdb_ingest_total 1\n"))
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if status := client.CheckHealth(context.Background()); !status.OK || status.ServerURL != server.URL {
		t.Fatalf("health status = %+v", status)
	}
	roots, err := client.ListRoots(context.Background(), 7)
	if err != nil {
		t.Fatalf("ListRoots: %v", err)
	}
	if len(roots) != 1 || roots[0].BatchID != "batch-1" {
		t.Fatalf("roots = %+v", roots)
	}
	rootPage, err := client.ListRootsPage(context.Background(), ListPageOptions{Limit: 7, Direction: RecordListDirectionDesc})
	if err != nil {
		t.Fatalf("ListRootsPage: %v", err)
	}
	if rootPage.NextCursor != "root-next" || len(rootPage.Roots) != 1 {
		t.Fatalf("root page = %+v", rootPage)
	}
	latest, err := client.LatestRoot(context.Background())
	if err != nil {
		t.Fatalf("LatestRoot: %v", err)
	}
	if latest.BatchID != "batch-latest" {
		t.Fatalf("latest = %+v", latest)
	}
	sths, err := client.ListSTHs(context.Background(), ListPageOptions{Limit: 5})
	if err != nil {
		t.Fatalf("ListSTHs: %v", err)
	}
	if len(sths.STHs) != 1 || sths.NextCursor != "sth-next" {
		t.Fatalf("sths = %+v", sths)
	}
	leaves, err := client.ListGlobalLeaves(context.Background(), ListPageOptions{Limit: 5})
	if err != nil {
		t.Fatalf("ListGlobalLeaves: %v", err)
	}
	if len(leaves.Leaves) != 1 || leaves.NextCursor != "leaf-next" {
		t.Fatalf("leaves = %+v", leaves)
	}
	anchors, err := client.ListAnchors(context.Background(), ListPageOptions{Limit: 5})
	if err != nil {
		t.Fatalf("ListAnchors: %v", err)
	}
	if len(anchors.Anchors) != 1 || anchors.NextCursor != "anchor-next" || anchors.Anchors[0].TreeSize != 4 || anchors.Anchors[0].Status != model.AnchorStatePublished || anchors.Anchors[0].Result == nil || anchors.Anchors[0].Result.AnchorID != "anchor-4" {
		t.Fatalf("anchors = %+v", anchors)
	}
	anchorStatus, err := client.GetAnchor(context.Background(), 4)
	if err != nil {
		t.Fatalf("GetAnchor: %v", err)
	}
	if anchorStatus.TreeSize != 4 || anchorStatus.Status != model.AnchorStatePublished || anchorStatus.Result == nil || anchorStatus.Result.AnchorID != "anchor-4" {
		t.Fatalf("anchor status = %+v", anchorStatus)
	}
	systems, err := client.ListAnchorSystems(context.Background())
	if err != nil || len(systems) != 1 || systems[0].SystemID != "chain-a" {
		t.Fatalf("ListAnchorSystems()=%+v err=%v", systems, err)
	}
	system, err := client.GetAnchorSystem(context.Background(), "chain-a")
	if err != nil || system.Kind != model.AnchorSystemKindEvidenceBlockchain {
		t.Fatalf("GetAnchorSystem()=%+v err=%v", system, err)
	}
	systemStatus, err := client.GetAnchorSystemStatus(context.Background(), "chain-a")
	if err != nil || systemStatus.State != model.AnchorSystemStateHealthy {
		t.Fatalf("GetAnchorSystemStatus()=%+v err=%v", systemStatus, err)
	}
	resourcePage, err := client.ListAnchorSystemResources(context.Background(), "chain-a", AnchorResourceListOptions{Kind: model.AnchorResourceKindNode, Limit: 5})
	if err != nil || len(resourcePage.Resources) != 1 || resourcePage.Resources[0].ResourceID != "node-1" {
		t.Fatalf("ListAnchorSystemResources()=%+v err=%v", resourcePage, err)
	}
	resource, err := client.GetAnchorSystemResource(context.Background(), "chain-a", model.AnchorResourceKindNode, "node-1")
	if err != nil || resource.Status != "online" {
		t.Fatalf("GetAnchorSystemResource()=%+v err=%v", resource, err)
	}
	metrics, err := client.MetricsRaw(context.Background())
	if err != nil {
		t.Fatalf("MetricsRaw: %v", err)
	}
	if !strings.Contains(metrics, "trustdb_ingest_total") {
		t.Fatalf("metrics = %q", metrics)
	}
}

func sdkHTTPTestAnchorSystem() model.AnchorSystem {
	return model.AnchorSystem{SchemaVersion: model.SchemaAnchorSystem, SystemID: "chain-a", SinkName: "chain", DisplayName: "Chain A", Kind: model.AnchorSystemKindEvidenceBlockchain, Capabilities: []string{model.AnchorCapabilityNodeRead}}
}

func TestHTTPTransportRejectsLegacyAnchorQueueEnvelope(t *testing.T) {
	t.Parallel()
	result := &STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 4, AnchorID: "anchor-4"}
	legacy := map[string]any{
		"tree_size":   4,
		"status":      model.AnchorStatePublished,
		"proof_level": ProofLevelL5,
		"result":      result,
		"outbox":      map[string]any{"tree_size": 4, "status": model.AnchorStatePublished},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/anchors/sth/4":
			writeJSONForTest(t, w, http.StatusOK, legacy)
		case "/v1/anchors/sth":
			writeJSONForTest(t, w, http.StatusOK, map[string]any{
				"anchors": []any{legacy}, "limit": 5, "direction": "desc",
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.GetAnchor(context.Background(), 4); err == nil || !strings.Contains(err.Error(), "outbox") {
		t.Fatalf("GetAnchor legacy response error = %v, want unknown outbox field", err)
	}
	if _, err := client.ListAnchors(context.Background(), ListPageOptions{Limit: 5}); err == nil || !strings.Contains(err.Error(), "outbox") {
		t.Fatalf("ListAnchors legacy response error = %v, want unknown outbox field", err)
	}
}

func TestHTTPTransportRejectsIncompleteAnchorEnvelope(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONForTest(t, w, http.StatusOK, anchorEnvelope{
			TreeSize: 4, Status: model.AnchorStatePending, ProofLevel: ProofLevelL5,
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.GetAnchor(context.Background(), 4); err == nil || !strings.Contains(err.Error(), "non-published") {
		t.Fatalf("GetAnchor incomplete response error = %v, want non-published failure", err)
	}
}

func TestHTTPTransportNilContextUsesDefaultTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		writeJSONForTest(t, w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("CheckHealth(nil) panicked: %v", recovered)
		}
	}()
	if status := client.CheckHealth(nil); !status.OK || status.ServerURL != server.URL {
		t.Fatalf("health status = %+v", status)
	}
}

func TestClientMetricsRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20+1)))
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.MetricsRaw(context.Background())
	if err == nil || !strings.Contains(err.Error(), "response body too large") {
		t.Fatalf("MetricsRaw() error = %v, want response body too large", err)
	}
}

func TestClientExportSingleProofFallsBackToL3WhenGlobalProofUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/proofs/tr1record":
			writeJSONForTest(t, w, http.StatusOK, proofEnvelope{
				RecordID:   "tr1record",
				ProofLevel: ProofLevelL3,
				ProofBundle: ProofBundle{
					SchemaVersion: model.SchemaProofBundle,
					RecordID:      "tr1record",
					CommittedReceipt: CommittedReceipt{
						BatchID: "batch-1",
					},
				},
			})
		case r.URL.Path == "/v1/global-log/evidence/batch-1":
			writeJSONForTest(t, w, http.StatusNotFound, map[string]string{
				"code":    string(trusterr.CodeNotFound),
				"message": "global proof not found",
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	proof, err := client.ExportSingleProof(context.Background(), "tr1record")
	if err != nil {
		t.Fatalf("ExportSingleProof: %v", err)
	}
	if proof.RecordID != "tr1record" || proof.ProofLevel != ProofLevelL3 || proof.GlobalProof != nil {
		t.Fatalf("proof = %+v", proof)
	}
}

func TestClientExportSingleProofUsesComposedGlobalEvidence(t *testing.T) {
	t.Parallel()
	bundle := ProofBundle{
		SchemaVersion: model.SchemaProofBundle,
		RecordID:      "tr1record",
		NodeID:        "node-1",
		LogID:         "log-1",
		CommittedReceipt: CommittedReceipt{
			BatchID:       "batch-1",
			BatchRoot:     make([]byte, 32),
			ClosedAtUnixN: 10,
		},
		BatchProof: model.BatchProof{TreeAlg: model.DefaultMerkleTreeAlg, TreeSize: 1},
	}
	leafHash, err := globallog.HashLeaf(model.GlobalLogLeaf{
		SchemaVersion:      model.SchemaGlobalLogLeaf,
		NodeID:             bundle.NodeID,
		LogID:              bundle.LogID,
		BatchID:            bundle.CommittedReceipt.BatchID,
		BatchRoot:          bundle.CommittedReceipt.BatchRoot,
		BatchTreeSize:      bundle.BatchProof.TreeSize,
		BatchClosedAtUnixN: bundle.CommittedReceipt.ClosedAtUnixN,
	})
	if err != nil {
		t.Fatalf("HashLeaf: %v", err)
	}
	sth := SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead,
		NodeID:        bundle.NodeID,
		LogID:         bundle.LogID,
		TreeSize:      1,
		RootHash:      leafHash,
		TreeAlg:       model.DefaultMerkleTreeAlg,
	}
	global := GlobalLogProof{
		SchemaVersion: model.SchemaGlobalLogProof,
		NodeID:        bundle.NodeID,
		LogID:         bundle.LogID,
		BatchID:       bundle.CommittedReceipt.BatchID,
		LeafHash:      leafHash,
		TreeSize:      1,
		STH:           sth,
	}
	anchored := STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		NodeID:        bundle.NodeID,
		LogID:         bundle.LogID,
		TreeSize:      1,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      anchor.DeterministicNoopAnchorID(sth),
		RootHash:      leafHash,
		STH:           sth,
	}
	transport := &exportEvidenceTransport{bundle: bundle, evidence: GlobalLogEvidence{GlobalProof: global, AnchorResult: &anchored}}
	client, err := NewClientWithTransport(transport)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	proof, err := client.ExportSingleProof(context.Background(), bundle.RecordID)
	if err != nil {
		t.Fatalf("ExportSingleProof: %v", err)
	}
	if proof.ProofLevel != ProofLevelL5 || proof.GlobalProof == nil || proof.AnchorResult == nil {
		t.Fatalf("proof=%+v", proof)
	}
	if transport.bundleCalls.Load() != 1 || transport.evidenceCalls.Load() != 1 {
		t.Fatalf("calls bundle=%d evidence=%d", transport.bundleCalls.Load(), transport.evidenceCalls.Load())
	}
}

func TestClientErrorIsDiagnosable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONForTest(t, w, http.StatusConflict, map[string]string{
			"code":    string(trusterr.CodeAlreadyExists),
			"message": "duplicate claim",
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.GetProofBundle(context.Background(), "tr1record")
	if err == nil {
		t.Fatal("GetProofBundle error = nil, want conflict")
	}
	var sdkErr *Error
	if !errors.As(err, &sdkErr) {
		t.Fatalf("error type = %T, want *sdk.Error", err)
	}
	if sdkErr.StatusCode != http.StatusConflict ||
		sdkErr.Code != string(trusterr.CodeAlreadyExists) ||
		!strings.Contains(sdkErr.Error(), "duplicate claim") {
		t.Fatalf("sdk error = %+v", sdkErr)
	}
}

func writeJSONForTest(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("Encode: %v", err)
	}
}
