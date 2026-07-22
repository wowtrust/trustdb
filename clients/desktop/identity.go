package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

// decodeKeyField accepts both base64-url (RawURL, what the CLI writes)
// and classic base64 with padding so a user can paste a key from any
// tool without us making them normalise it first.
func decodeKeyField(value string) ([]byte, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, errors.New("empty key")
	}
	if data, err := base64.RawURLEncoding.DecodeString(v); err == nil {
		return data, nil
	}
	if data, err := base64.StdEncoding.DecodeString(v); err == nil {
		return data, nil
	}
	if data, err := base64.URLEncoding.DecodeString(v); err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("invalid key: not valid base64")
}

func encodeKey(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func identityFromPrivate(priv ed25519.PrivateKey, tenantID, clientID, keyID string) (Identity, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Identity{}, fmt.Errorf("invalid ed25519 private key size: %d", len(priv))
	}
	pub := priv.Public().(ed25519.PublicKey)
	return Identity{
		TenantID:      strings.TrimSpace(tenantID),
		ClientID:      strings.TrimSpace(clientID),
		KeyID:         strings.TrimSpace(keyID),
		PrivateKeyB64: encodeKey(priv),
		PublicKeyB64:  encodeKey(pub),
	}, nil
}

// loadSigningKeys returns the ed25519 pair from the persisted identity
// so HTTP/verify flows never have to touch the base64 encoding.
func loadSigningKeys(id Identity) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if id.PrivateKeyB64 == "" {
		return nil, nil, errors.New("identity has no private key")
	}
	privBytes, err := decodeKeyField(id.PrivateKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("private key wrong size %d", len(privBytes))
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

func generateIdentity(tenantID, clientID, keyID string) (Identity, error) {
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		return Identity{}, err
	}
	return identityFromPrivate(priv, tenantID, clientID, keyID)
}
