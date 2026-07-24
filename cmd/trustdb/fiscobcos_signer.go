package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos/standardsdk"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

type fiscoBCOSAccountSignerBuilder func(
	context.Context,
	fiscobcos.AccountProviderConfig,
	trustconfig.SignerPlugins,
	io.Writer,
) (standardsdk.AccountSigner, io.Closer, error)

type fiscoBCOSPluginAccountSigner struct {
	process *signerplugin.Process
	key     signerplugin.Key
}

func newFISCOBCOSPluginAccountSigner(
	ctx context.Context,
	account fiscobcos.AccountProviderConfig,
	plugins trustconfig.SignerPlugins,
	stderr io.Writer,
) (standardsdk.AccountSigner, io.Closer, error) {
	if account.Algorithm != fiscobcos.StandardAccountAlg {
		return nil, nil, fmt.Errorf("FISCO BCOS account algorithm %q is not the standard-chain profile", account.Algorithm)
	}
	plugin, err := fiscoBCOSSignerPluginConfig(account.Provider, plugins)
	if err != nil {
		return nil, nil, err
	}
	startTimeout, err := time.ParseDuration(plugin.StartTimeout)
	if err != nil || startTimeout <= 0 {
		return nil, nil, fmt.Errorf("crypto.signer_plugins.%s.start_timeout is invalid", account.Provider)
	}
	rpcTimeout, err := time.ParseDuration(plugin.RPCTimeout)
	if err != nil || rpcTimeout <= 0 {
		return nil, nil, fmt.Errorf("crypto.signer_plugins.%s.rpc_timeout is invalid", account.Provider)
	}
	if plugin.MaxConcurrency < 0 || plugin.MaxConcurrency > 1024 {
		return nil, nil, fmt.Errorf("crypto.signer_plugins.%s.max_concurrency must be between 0 and 1024", account.Provider)
	}
	process, err := signerplugin.StartProcess(ctx, signerplugin.ProcessConfig{
		Command:                plugin.Command,
		Args:                   append([]string(nil), plugin.Args...),
		InheritEnv:             append([]string(nil), plugin.InheritEnv...),
		StartTimeout:           startTimeout,
		PublicKeyTimeout:       rpcTimeout,
		SignTimeout:            rpcTimeout,
		HostMaxConcurrentSigns: uint32(plugin.MaxConcurrency),
		Stderr:                 stderr,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start FISCO BCOS %s account signer plugin: %w", account.Provider, err)
	}
	key, err := fiscoBCOSPluginKey(account, process.Info())
	if err != nil {
		_ = process.Close()
		return nil, nil, err
	}
	signer := &fiscoBCOSPluginAccountSigner{process: process, key: key}
	return signer, signer, nil
}

func fiscoBCOSSignerPluginConfig(provider string, plugins trustconfig.SignerPlugins) (trustconfig.SignerPlugin, error) {
	var plugin trustconfig.SignerPlugin
	switch provider {
	case signerplugin.ProviderPKCS11:
		plugin = plugins.PKCS11
	case signerplugin.ProviderSDF:
		plugin = plugins.SDF
	case signerplugin.ProviderRemote:
		plugin = plugins.Remote
	default:
		return trustconfig.SignerPlugin{}, fmt.Errorf("unsupported non-exportable FISCO BCOS account provider %q", provider)
	}
	if strings.TrimSpace(plugin.Command) == "" {
		return trustconfig.SignerPlugin{}, fmt.Errorf("crypto.signer_plugins.%s.command is required for FISCO BCOS account provider %s", provider, provider)
	}
	return plugin, nil
}

func fiscoBCOSPluginKey(account fiscobcos.AccountProviderConfig, info signerplugin.GetInfoResponse) (signerplugin.Key, error) {
	reference, err := fiscoBCOSPluginKeyReference(account.Provider, account.KeyReference)
	if err != nil {
		return signerplugin.Key{}, err
	}
	key := signerplugin.Key{
		Binding: signerplugin.Binding{
			ProtocolVersion:   signerplugin.ProtocolVersion,
			PluginID:          info.PluginID,
			ProviderKind:      account.Provider,
			CryptoSuite:       signerplugin.SuiteFISCOBCOSStandard,
			Algorithm:         signerplugin.AlgorithmSecp256k1,
			PublicKeyEncoding: signerplugin.Secp256k1PublicKeyEncoding,
			SignatureEncoding: signerplugin.Secp256k1SignatureEncoding,
			KeyID:             account.KeyID,
		},
		Reference: reference,
	}
	if err := signerplugin.ValidateBindingForInfo(key.Binding, info); err != nil {
		return signerplugin.Key{}, fmt.Errorf("FISCO BCOS signer plugin profile mismatch: %w", err)
	}
	if err := signerplugin.ValidateKey(key); err != nil {
		return signerplugin.Key{}, fmt.Errorf("invalid FISCO BCOS account key reference: %w", err)
	}
	return key, nil
}

type fiscoBCOSSDFReference struct {
	DeviceRef     string `json:"device_ref"`
	KeyIndex      uint32 `json:"key_index"`
	CredentialRef string `json:"credential_ref"`
}

type fiscoBCOSRemoteReference struct {
	Endpoint      string `json:"endpoint"`
	Handle        string `json:"handle"`
	CredentialRef string `json:"credential_ref"`
}

func fiscoBCOSPluginKeyReference(provider, encoded string) (signerplugin.KeyReference, error) {
	switch provider {
	case signerplugin.ProviderPKCS11:
		return signerplugin.KeyReference{
			PKCS11: &signerplugin.PKCS11KeyReference{URI: encoded},
		}, nil
	case signerplugin.ProviderSDF:
		var reference fiscoBCOSSDFReference
		if err := unmarshalCanonicalJSONReference(encoded, &reference); err != nil {
			return signerplugin.KeyReference{}, fmt.Errorf("invalid canonical FISCO BCOS SDF key reference: %w", err)
		}
		return signerplugin.KeyReference{SDF: &signerplugin.SDFKeyReference{
			DeviceRef: reference.DeviceRef, KeyIndex: reference.KeyIndex, CredentialRef: reference.CredentialRef,
		}}, nil
	case signerplugin.ProviderRemote:
		var reference fiscoBCOSRemoteReference
		if err := unmarshalCanonicalJSONReference(encoded, &reference); err != nil {
			return signerplugin.KeyReference{}, fmt.Errorf("invalid canonical FISCO BCOS remote key reference: %w", err)
		}
		return signerplugin.KeyReference{Remote: &signerplugin.RemoteKeyReference{
			Endpoint: reference.Endpoint, Handle: reference.Handle, CredentialRef: reference.CredentialRef,
		}}, nil
	default:
		return signerplugin.KeyReference{}, fmt.Errorf("unsupported FISCO BCOS account provider %q", provider)
	}
}

func unmarshalCanonicalJSONReference(encoded string, target any) error {
	data := []byte(encoded)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("reference is not canonical JSON")
	}
	return nil
}

func (s *fiscoBCOSPluginAccountSigner) PublicKey(ctx context.Context) ([]byte, error) {
	if s == nil || s.process == nil {
		return nil, fmt.Errorf("FISCO BCOS signer plugin is closed")
	}
	return s.process.GetPublicKey(ctx, s.key)
}

func (s *fiscoBCOSPluginAccountSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if s == nil || s.process == nil {
		return nil, fmt.Errorf("FISCO BCOS signer plugin is closed")
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("FISCO BCOS signer digest must be 32 bytes")
	}
	return s.process.Sign(ctx, s.key, digest)
}

func (s *fiscoBCOSPluginAccountSigner) Close() error {
	if s == nil || s.process == nil {
		return nil
	}
	process := s.process
	s.process = nil
	return process.Close()
}
