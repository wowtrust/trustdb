package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func (rt *runtimeConfig) signerResolverForConfig() (*keydescriptor.Resolver, error) {
	if rt.signerResolver != nil {
		return rt.signerResolver, nil
	}
	software, err := keydescriptor.NewSoftwareProvider(keyenvelope.NewPassphraseKEKProvider(
		keyenvelope.DefaultPassphraseSource(),
	))
	if err != nil {
		return nil, err
	}
	providers := []keydescriptor.SignerProvider{software}
	configured := []struct {
		name   string
		plugin trustconfig.SignerPlugin
	}{
		{name: keydescriptor.ProviderRemote, plugin: rt.cfg.Crypto.SignerPlugins.Remote},
		{name: keydescriptor.ProviderPKCS11, plugin: rt.cfg.Crypto.SignerPlugins.PKCS11},
		{name: keydescriptor.ProviderSDF, plugin: rt.cfg.Crypto.SignerPlugins.SDF},
	}
	for _, item := range configured {
		if strings.TrimSpace(item.plugin.Command) == "" {
			continue
		}
		provider, err := configuredPluginProvider(item.name, item.plugin, rt.errOut)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	resolver, err := keydescriptor.NewResolver(providers...)
	if err != nil {
		return nil, err
	}
	rt.signerResolver = resolver
	return resolver, nil
}

func configuredPluginProvider(name string, config trustconfig.SignerPlugin, stderr io.Writer) (*keydescriptor.PluginSignerProvider, error) {
	startTimeout, err := time.ParseDuration(config.StartTimeout)
	if err != nil || startTimeout <= 0 {
		return nil, fmt.Errorf("crypto.signer_plugins.%s.start_timeout is invalid", name)
	}
	rpcTimeout, err := time.ParseDuration(config.RPCTimeout)
	if err != nil || rpcTimeout <= 0 {
		return nil, fmt.Errorf("crypto.signer_plugins.%s.rpc_timeout is invalid", name)
	}
	if config.MaxConcurrency < 0 || config.MaxConcurrency > 1024 {
		return nil, fmt.Errorf("crypto.signer_plugins.%s.max_concurrency must be between 0 and 1024", name)
	}
	return keydescriptor.NewPluginSignerProvider(keydescriptor.SignerPluginOptions{
		Provider:       name,
		Command:        config.Command,
		Args:           append([]string(nil), config.Args...),
		InheritEnv:     append([]string(nil), config.InheritEnv...),
		StartTimeout:   startTimeout,
		RPCTimeout:     rpcTimeout,
		MaxConcurrency: uint32(config.MaxConcurrency),
		Stderr:         stderr,
	})
}

func (rt *runtimeConfig) readSigner(ctx context.Context, path string) (trustcrypto.Signer, keydescriptor.Descriptor, error) {
	resolver, err := rt.signerResolverForConfig()
	if err != nil {
		return nil, keydescriptor.Descriptor{}, err
	}
	signer, descriptor, err := resolver.ResolveSignerFile(ctx, path)
	if err != nil {
		_ = rt.closeSignerResolver()
		return nil, keydescriptor.Descriptor{}, err
	}
	return signer, descriptor, nil
}

func (rt *runtimeConfig) readLifecycleSigner(ctx context.Context, path string) (trustcrypto.Signer, keydescriptor.Descriptor, error) {
	resolver, err := rt.signerResolverForConfig()
	if err != nil {
		return nil, keydescriptor.Descriptor{}, err
	}
	signer, descriptor, err := resolver.ResolveLifecycleSignerFile(ctx, path)
	if err != nil {
		_ = rt.closeSignerResolver()
		return nil, keydescriptor.Descriptor{}, err
	}
	return signer, descriptor, nil
}

func (rt *runtimeConfig) closeSignerResolver() error {
	if rt == nil || rt.signerResolver == nil {
		return nil
	}
	resolver := rt.signerResolver
	rt.signerResolver = nil
	return resolver.Close()
}
