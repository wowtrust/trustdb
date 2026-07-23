package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk"
)

const pollInterval = 100 * time.Millisecond

type options struct {
	serverURL        string
	filePath         string
	clientPrivateKey string
	clientPublicKey  string
	serverPublicKey  string
	outputPath       string
	tenantID         string
	clientID         string
	keyID            string
	timeout          time.Duration
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "sdk-onboarding: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}

	clientSigner, clientSignerDescriptor, err := keydescriptor.NewDefaultResolver().ResolveSignerFile(context.Background(), opts.clientPrivateKey)
	if err != nil {
		return fmt.Errorf("resolve client signer descriptor: %w", err)
	}
	if clientSignerDescriptor.KeyID != opts.keyID {
		return fmt.Errorf("client signer descriptor key_id %q does not match --key-id %q", clientSignerDescriptor.KeyID, opts.keyID)
	}
	clientPublicKey, err := readPublicKey(opts.clientPublicKey)
	if err != nil {
		return err
	}
	serverPublicKey, err := readPublicKey(opts.serverPublicKey)
	if err != nil {
		return err
	}
	resolvedClientPublic, err := clientSigner.PublicKey(context.Background())
	if err != nil {
		return fmt.Errorf("read client signer public key: %w", err)
	}
	if !bytes.Equal(resolvedClientPublic.Bytes, clientPublicKey) {
		return errors.New("client signer and verifier descriptors do not identify the same Ed25519 key")
	}

	client, err := sdk.NewClient(opts.serverURL)
	if err != nil {
		return fmt.Errorf("create SDK client: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	if err := client.Health(ctx); err != nil {
		return fmt.Errorf("check server health: %w", err)
	}

	result, err := submitFile(ctx, client, opts, clientSigner)
	if err != nil {
		return err
	}
	fmt.Printf("submitted record_id=%s proof_level=%s\n", result.RecordID, result.ProofLevel)
	if !result.BatchEnqueued {
		if result.BatchError != "" {
			return fmt.Errorf("record was accepted but not queued for proof generation: %s", result.BatchError)
		}
		return errors.New("record was accepted but not queued for proof generation")
	}

	proof, err := waitForGlobalProof(ctx, client, result.RecordID)
	if err != nil {
		return err
	}
	if err := sdk.WriteSingleProofFile(opts.outputPath, proof); err != nil {
		return fmt.Errorf("write proof file: %w", err)
	}

	writtenProof, err := sdk.ReadSingleProofFile(opts.outputPath)
	if err != nil {
		return fmt.Errorf("read proof file: %w", err)
	}
	original, err := os.Open(opts.filePath)
	if err != nil {
		return fmt.Errorf("reopen original file: %w", err)
	}
	verified, verifyErr := sdk.VerifySingleProof(original, writtenProof, sdk.TrustedKeys{
		ClientPublicKey: clientPublicKey,
		ServerPublicKey: serverPublicKey,
	}, sdk.VerifyOptions{})
	closeErr := original.Close()
	if verifyErr != nil {
		return fmt.Errorf("verify proof with local trust roots: %w", verifyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close original file: %w", closeErr)
	}
	if !verified.Valid {
		return errors.New("proof verification returned an invalid result")
	}
	if verified.RecordID != result.RecordID {
		return fmt.Errorf("verified record ID %q does not match submitted record ID %q", verified.RecordID, result.RecordID)
	}

	fmt.Printf("verified record_id=%s proof_level=%s output=%s\n", verified.RecordID, verified.ProofLevel, opts.outputPath)
	return nil
}

func parseFlags(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("sdk-onboarding", flag.ContinueOnError)
	flags.StringVar(&opts.serverURL, "server", "http://127.0.0.1:8080", "TrustDB server URL")
	flags.StringVar(&opts.filePath, "file", "", "original file to submit and verify (required)")
	flags.StringVar(&opts.clientPrivateKey, "client-private-key", "", "TrustDB client signer descriptor (required)")
	flags.StringVar(&opts.clientPublicKey, "client-public-key", "", "TrustDB client verifier descriptor (required)")
	flags.StringVar(&opts.serverPublicKey, "server-public-key", "", "TrustDB server verifier descriptor (required)")
	flags.StringVar(&opts.outputPath, "output", "proof.sproof", "output .sproof path")
	flags.StringVar(&opts.tenantID, "tenant", "default", "claim tenant ID")
	flags.StringVar(&opts.clientID, "client", "sdk-onboarding", "claim client ID")
	flags.StringVar(&opts.keyID, "key-id", "client-key", "claim signing key ID")
	flags.DurationVar(&opts.timeout, "timeout", 30*time.Second, "overall network and proof wait timeout")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	for name, value := range map[string]string{
		"file":               opts.filePath,
		"client-private-key": opts.clientPrivateKey,
		"client-public-key":  opts.clientPublicKey,
		"server-public-key":  opts.serverPublicKey,
		"output":             opts.outputPath,
		"tenant":             opts.tenantID,
		"client":             opts.clientID,
		"key-id":             opts.keyID,
	} {
		if strings.TrimSpace(value) == "" {
			return options{}, fmt.Errorf("--%s must not be empty", name)
		}
	}
	if opts.timeout <= 0 {
		return options{}, errors.New("--timeout must be greater than zero")
	}
	return opts, nil
}

func submitFile(ctx context.Context, client *sdk.Client, opts options, signer trustcrypto.Signer) (sdk.SubmitResult, error) {
	original, err := os.Open(opts.filePath)
	if err != nil {
		return sdk.SubmitResult{}, fmt.Errorf("open original file: %w", err)
	}
	contentHash, contentLength, hashErr := trustcrypto.HashReader(model.DefaultHashAlg, original)
	closeErr := original.Close()
	if hashErr != nil {
		return sdk.SubmitResult{}, fmt.Errorf("hash original file: %w", hashErr)
	}
	if closeErr != nil {
		return sdk.SubmitResult{}, fmt.Errorf("close original file: %w", closeErr)
	}
	nonce, err := trustcrypto.NewNonce(16)
	if err != nil {
		return sdk.SubmitResult{}, err
	}
	idempotencyBytes, err := trustcrypto.NewNonce(18)
	if err != nil {
		return sdk.SubmitResult{}, err
	}
	claimValue, err := claim.NewFileClaim(
		opts.tenantID,
		opts.clientID,
		opts.keyID,
		time.Now().UTC(),
		nonce,
		"sdk-"+base64.RawURLEncoding.EncodeToString(idempotencyBytes),
		model.Content{
			HashAlg:       model.DefaultHashAlg,
			ContentHash:   contentHash,
			ContentLength: contentLength,
			MediaType:     "application/octet-stream",
			StorageURI:    opts.filePath,
		},
		model.Metadata{EventType: "file.snapshot", Source: "sdk-onboarding"},
	)
	if err != nil {
		return sdk.SubmitResult{}, err
	}
	signed, err := claim.SignWithSigner(ctx, claimValue, signer)
	if err != nil {
		return sdk.SubmitResult{}, fmt.Errorf("sign claim: %w", err)
	}
	result, err := client.SubmitSignedClaim(ctx, signed)
	if err != nil {
		return sdk.SubmitResult{}, fmt.Errorf("submit signed claim: %w", err)
	}
	return result, nil
}

func waitForGlobalProof(ctx context.Context, client *sdk.Client, recordID string) (sdk.SingleProof, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	lastLevel := "not available"
	for {
		proof, err := client.ExportSingleProof(ctx, recordID)
		switch {
		case err == nil && proof.GlobalProof != nil:
			return proof, nil
		case err == nil:
			lastLevel = proof.ProofLevel
		case sdk.IsUnavailable(err):
			// L3/L4 materialization is asynchronous. Retry only the documented
			// not-ready responses; other errors should fail immediately.
		default:
			return sdk.SingleProof{}, fmt.Errorf("export proof: %w", err)
		}

		select {
		case <-ctx.Done():
			return sdk.SingleProof{}, fmt.Errorf("wait for an L4 proof (last level: %s): %w", lastLevel, ctx.Err())
		case <-ticker.C:
		}
	}
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	descriptor, err := keydescriptor.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if descriptor.Kind != keydescriptor.KindVerifier || descriptor.Provider != keydescriptor.ProviderPublic ||
		descriptor.CryptoSuite != cryptosuite.INTLV1 || descriptor.Algorithm != cryptosuite.SignatureEd25519 {
		return nil, fmt.Errorf("public key descriptor %s is not an INTL_V1 Ed25519 verifier", path)
	}
	return ed25519.PublicKey(append([]byte(nil), descriptor.PublicKey.Bytes...)), nil
}
