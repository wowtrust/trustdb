package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/verify"
	"github.com/spf13/cobra"
)

// httpFetchTimeout bounds a single GET against the TrustDB server.
// Verify is intended for interactive/CI use so a conservative timeout
// gives the user a clear failure mode if the server is unreachable.
const (
	httpFetchTimeout           = 10 * time.Second
	maxVerifyHTTPResponseBytes = 16 << 20
)

func newVerifyCommand(rt *runtimeConfig) *cobra.Command {
	var (
		filePath, sproofPath, proofPath, globalProofPath, anchorPath string
		clientPubPath, registryPath, registryPubPath                 string
		serverPubPath                                                string
		serverURL, recordID                                          string
		skipAnchor                                                   bool
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a file against a TrustDB proof bundle (optionally up to L5)",
		// Root sets SilenceUsage/SilenceErrors at the parent; set
		// them here too so unit-testing the subcommand directly
		// (with cmd.Execute()) does not spam stderr with cobra's
		// auto-printed usage banner on flag-validation errors.
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Verify a content file against a TrustDB proof bundle.

Two modes are supported:

  Local mode (default):
    --file <path> --sproof <proof.sproof>
    --file <path> --proof <bundle.tdproof> [--global-proof <global.tdgproof>] [--anchor <anchor.tdanchor>]

  Server mode:
    --file <path> --server <url> --record <record_id>

Both modes require the server public key and either an explicit
client public key or a key registry for resolving the client key
recorded in the bundle. When an anchor is available (either via
--anchor in local mode or auto-fetched in server mode) the result
is upgraded to L5; pass --skip-anchor to ignore L5 anchors in server mode
or inside a local .sproof.
L5 always verifies an STH/global-root anchor; local --anchor requires
--global-proof because batch roots are no longer directly anchored.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientPubPath = stringOrConfig(cmd, rt, "client-public-key", clientPubPath, "keys.client_public")
			registryPath = stringOrConfig(cmd, rt, "key-registry", registryPath, "key_registry")
			registryPubPath = stringOrConfig(cmd, rt, "registry-public-key", registryPubPath, "keys.registry_public")
			serverPubPath = stringOrConfig(cmd, rt, "server-public-key", serverPubPath, "keys.server_public")

			if filePath == "" || serverPubPath == "" {
				return usageError("verify requires file and server-public-key")
			}
			if clientPubPath == "" && registryPath == "" {
				return usageError("verify requires either client-public-key or key-registry")
			}

			remote := serverURL != ""
			switch {
			case remote && recordID == "":
				return usageError("verify --server requires --record")
			case remote && sproofPath != "":
				return usageError("verify: --sproof and --server are mutually exclusive")
			case remote && proofPath != "":
				return usageError("verify: --proof and --server are mutually exclusive")
			case remote && globalProofPath != "":
				return usageError("verify: --global-proof is only valid in local mode")
			case remote && anchorPath != "":
				return usageError("verify: --anchor is only valid in local mode; use --skip-anchor to disable remote fetch")
			case !remote && sproofPath == "" && proofPath == "":
				return usageError("verify requires --sproof, --proof, or --server/--record")
			case !remote && sproofPath != "" && proofPath != "":
				return usageError("verify: --sproof and --proof are mutually exclusive")
			case !remote && sproofPath != "" && globalProofPath != "":
				return usageError("verify: --global-proof is only valid with --proof")
			case !remote && sproofPath != "" && anchorPath != "":
				return usageError("verify: --anchor is only valid with --proof")
			case !remote && anchorPath != "" && globalProofPath == "":
				return usageError("verify: --anchor requires --global-proof")
			}

			bundle, globalProof, remoteAnchor, err := loadVerifyInputs(
				cmd.Context(),
				remote,
				sproofPath,
				proofPath,
				globalProofPath,
				serverURL,
				recordID,
				skipAnchor,
			)
			if err != nil {
				return err
			}

			clientPub, err := resolveVerifyClientPub(bundle, clientPubPath, registryPath, registryPubPath)
			if err != nil {
				return err
			}
			serverPub, err := readPublicKey(serverPubPath)
			if err != nil {
				return err
			}
			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()

			opts := []verify.Option{}
			var anchorInUse *model.STHAnchorResult
			if globalProof != nil {
				opts = append(opts, verify.WithGlobalProof(*globalProof))
			}
			switch {
			case !remote && anchorPath != "":
				var ar model.STHAnchorResult
				if err := readCBORFile(anchorPath, &ar); err != nil {
					return fmt.Errorf("read anchor result: %w", err)
				}
				opts = append(opts, verify.WithAnchor(ar))
				anchorInUse = &ar
			case remoteAnchor != nil:
				opts = append(opts, verify.WithAnchor(*remoteAnchor))
				anchorInUse = remoteAnchor
			}

			result, err := verify.ProofBundle(f, bundle, verify.TrustedKeys{
				ClientPublicKey: clientPub,
				ServerPublicKey: serverPub,
			}, opts...)
			if err != nil {
				return err
			}

			logEvent := rt.logger.Info().
				Str("record_id", result.RecordID).
				Str("level", result.ProofLevel)
			if anchorInUse != nil {
				logEvent = logEvent.
					Str("anchor_sink", anchorInUse.SinkName).
					Str("anchor_id", anchorInUse.AnchorID)
			}
			logEvent.Msg("verified proof")
			return rt.writeJSON(result)
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "file to verify")
	cmd.Flags().StringVar(&sproofPath, "sproof", "", "single proof path (local mode, recommended)")
	cmd.Flags().StringVar(&proofPath, "proof", "", "proof bundle path (local mode)")
	cmd.Flags().StringVar(&globalProofPath, "global-proof", "", "global log proof path (local mode; required with --anchor)")
	cmd.Flags().StringVar(&anchorPath, "anchor", "", "anchor result path (local mode, optional)")
	cmd.Flags().StringVar(&clientPubPath, "client-public-key", "", "client public key")
	cmd.Flags().StringVar(&registryPath, "key-registry", "", "key registry path")
	cmd.Flags().StringVar(&registryPubPath, "registry-public-key", "", "registry public key")
	cmd.Flags().StringVar(&serverPubPath, "server-public-key", "", "server public key")
	cmd.Flags().StringVar(&serverURL, "server", "", "TrustDB server URL (remote mode)")
	cmd.Flags().StringVar(&recordID, "record", "", "record id to verify (remote mode)")
	cmd.Flags().BoolVar(&skipAnchor, "skip-anchor", false, "do not fetch or verify L5 anchor")
	return cmd
}

// loadVerifyInputs dispatches between local-file and HTTP-fetch modes
// and returns the bundle plus — in remote mode — the anchor result if
// one exists. Remote mode treats a missing anchor as "not yet
// anchored", not as an error, so operators can verify committed
// batches whose anchor is still pending.
func loadVerifyInputs(
	ctx context.Context,
	remote bool,
	sproofPath, proofPath, globalProofPath, serverURL, recordID string,
	skipAnchor bool,
) (model.ProofBundle, *model.GlobalLogProof, *model.STHAnchorResult, error) {
	if !remote {
		if sproofPath != "" {
			proof, err := sproof.ReadFile(sproofPath)
			if err != nil {
				return model.ProofBundle{}, nil, nil, err
			}
			if skipAnchor {
				return proof.ProofBundle, proof.GlobalProof, nil, nil
			}
			return proof.ProofBundle, proof.GlobalProof, proof.AnchorResult, nil
		}
		var bundle model.ProofBundle
		if err := readCBORFile(proofPath, &bundle); err != nil {
			return model.ProofBundle{}, nil, nil, err
		}
		if globalProofPath == "" {
			return bundle, nil, nil, nil
		}
		var global model.GlobalLogProof
		if err := readCBORFile(globalProofPath, &global); err != nil {
			return model.ProofBundle{}, nil, nil, err
		}
		return bundle, &global, nil, nil
	}
	client := &http.Client{Timeout: httpFetchTimeout}
	bundle, err := fetchProofBundle(ctx, client, serverURL, recordID)
	if err != nil {
		return model.ProofBundle{}, nil, nil, err
	}
	global, err := fetchGlobalProof(ctx, client, serverURL, bundle.CommittedReceipt.BatchID)
	if err != nil {
		return model.ProofBundle{}, nil, nil, err
	}
	if skipAnchor {
		return bundle, &global, nil, nil
	}
	ar, err := fetchAnchorResult(ctx, client, serverURL, global.STH.TreeSize)
	if err != nil {
		return model.ProofBundle{}, nil, nil, err
	}
	return bundle, &global, ar, nil
}

type proofResponseEnvelope struct {
	RecordID    string            `json:"record_id"`
	ProofLevel  string            `json:"proof_level"`
	ProofBundle model.ProofBundle `json:"proof_bundle"`
}

type anchorResponseEnvelope struct {
	TreeSize uint64                 `json:"tree_size"`
	Status   string                 `json:"status"`
	Result   *model.STHAnchorResult `json:"result,omitempty"`
}

// fetchProofBundle retrieves /v1/proofs/{record_id} and unwraps the
// JSON envelope into a concrete ProofBundle. The server uses the same
// JSON shape in both local and remote clients, so a successful decode
// here is effectively a smoke test of the API schema.
func fetchProofBundle(ctx context.Context, client *http.Client, serverURL, recordID string) (model.ProofBundle, error) {
	endpoint, err := joinURL(serverURL, "/v1/proofs/", recordID)
	if err != nil {
		return model.ProofBundle{}, err
	}
	var env proofResponseEnvelope
	if err := getJSON(ctx, client, endpoint, &env); err != nil {
		return model.ProofBundle{}, fmt.Errorf("fetch proof bundle: %w", err)
	}
	if env.ProofBundle.RecordID == "" {
		return model.ProofBundle{}, fmt.Errorf("verify: server returned empty proof bundle for record %s", recordID)
	}
	return env.ProofBundle, nil
}

func fetchGlobalProof(ctx context.Context, client *http.Client, serverURL, batchID string) (model.GlobalLogProof, error) {
	if batchID == "" {
		return model.GlobalLogProof{}, fmt.Errorf("verify: proof bundle has empty batch_id")
	}
	endpoint, err := joinURL(serverURL, "/v1/global-log/inclusion/", batchID)
	if err != nil {
		return model.GlobalLogProof{}, err
	}
	var proof model.GlobalLogProof
	if err := getJSON(ctx, client, endpoint, &proof); err != nil {
		return model.GlobalLogProof{}, fmt.Errorf("fetch global log proof: %w", err)
	}
	return proof, nil
}

// fetchAnchorResult retrieves /v1/anchors/sth/{tree_size} and returns the
// embedded STHAnchorResult when present. A 404 or a present-but-pending
// entry is reported as (nil, nil) because the caller then falls back
// to L4 verification, which is a legitimate state for a freshly
// committed batch whose STH anchor worker has not yet published.
func fetchAnchorResult(ctx context.Context, client *http.Client, serverURL string, treeSize uint64) (*model.STHAnchorResult, error) {
	if treeSize == 0 {
		return nil, nil
	}
	endpoint, err := joinURL(serverURL, "/v1/anchors/sth/", fmt.Sprintf("%d", treeSize))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch anchor: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, nil
	case http.StatusPreconditionFailed:
		// Anchor service disabled on the server; treat as "no
		// anchor to verify" rather than a hard failure so the
		// verify command still works against a pre-L5 server.
		return nil, nil
	case http.StatusOK:
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("verify: GET %s: %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
	}
	var env anchorResponseEnvelope
	if err := decodeSingleJSON(resp.Body, &env); err != nil {
		return nil, fmt.Errorf("decode anchor response: %w", err)
	}
	if env.Result == nil {
		return nil, nil
	}
	return env.Result, nil
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("GET %s: %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
	}
	return decodeSingleJSON(resp.Body, dst)
}

func decodeSingleJSON(r io.Reader, dst any) error {
	return decodeSingleJSONLimit(r, dst, maxVerifyHTTPResponseBytes)
}

func decodeSingleJSONLimit(r io.Reader, dst any, limit int64) error {
	if limit <= 0 {
		return fmt.Errorf("response body limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("response body too large: %d > %d", len(body), limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("trailing JSON data")
	} else if err != io.EOF {
		return err
	}
	return nil
}

// joinURL concatenates a base URL (e.g. "http://host:8080") with a
// path prefix and an opaque suffix, percent-encoding the suffix so
// that record/batch ids containing odd characters still produce a
// valid request URL.
func joinURL(base, prefix, suffix string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse server url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("server url must include scheme and host: %s", base)
	}
	u.Path = strings.TrimRight(u.Path, "/") + prefix + url.PathEscape(suffix)
	return u.String(), nil
}

func resolveVerifyClientPub(bundle model.ProofBundle, clientPubPath, registryPath, registryPubPath string) (ed25519.PublicKey, error) {
	if clientPubPath != "" {
		return readPublicKey(clientPubPath)
	}
	if registryPath != "" {
		var registryPub ed25519.PublicKey
		var err error
		if registryPubPath != "" {
			registryPub, err = readPublicKey(registryPubPath)
			if err != nil {
				return nil, err
			}
		}
		reg, err := keystore.Open(registryPath, "", nil, registryPub)
		if err != nil {
			return nil, err
		}
		key, err := reg.LookupClientKeyAt(
			bundle.SignedClaim.Claim.TenantID,
			bundle.SignedClaim.Claim.ClientID,
			bundle.SignedClaim.Claim.KeyID,
			time.Unix(0, bundle.AcceptedReceipt.ReceivedAtUnixN),
		)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(key.PublicKey), nil
	}
	return nil, usageError("verify requires either client-public-key or key-registry")
}
