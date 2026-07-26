package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/securityaudit"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func (rt *runtimeConfig) resolvePolicyCheckedSigner(
	ctx context.Context,
	path string,
	role string,
) (trustcrypto.Signer, keydescriptor.Descriptor, error) {
	descriptor, err := keydescriptor.ReadFile(path)
	if err != nil {
		return nil, keydescriptor.Descriptor{}, err
	}
	endpoint := ""
	if descriptor.Provider == keydescriptor.ProviderRemote && descriptor.Remote != nil {
		endpoint = descriptor.Remote.Endpoint
	}
	if err := trustconfig.ValidateDeploymentKey(
		rt.cfg.RunProfile,
		rt.cfg.DeploymentPolicy,
		role,
		string(descriptor.CryptoSuite),
		descriptor.Provider,
		endpoint,
	); err != nil {
		return nil, keydescriptor.Descriptor{}, fmt.Errorf("deployment policy: %w", err)
	}
	signer, err := rt.resolveSignerDescriptor(ctx, path, descriptor)
	if err != nil {
		return nil, keydescriptor.Descriptor{}, err
	}
	return signer, descriptor, nil
}

func validateServeDeploymentPolicy(
	ctx context.Context,
	rt *runtimeConfig,
	serverKey keydescriptor.Descriptor,
	metastoreKind string,
	tikvPDAddresses []string,
	anchorSink string,
	trust *fiscobcos.TrustConfig,
) error {
	if !trustconfig.IsStrictDeploymentProfile(rt.cfg.RunProfile) {
		return nil
	}
	runtime := trustconfig.DeploymentRuntime{
		ServerCryptoSuite: string(serverKey.CryptoSuite),
		ServerKeyProvider: serverKey.Provider,
		AuditCryptoSuite:  string(rt.auditKey.CryptoSuite),
		AuditKeyProvider:  rt.auditKey.Provider,
		AnchorSink:        strings.ToLower(strings.TrimSpace(anchorSink)),
		StorageBackend:    strings.ToLower(strings.TrimSpace(metastoreKind)),
	}
	if serverKey.Provider == keydescriptor.ProviderRemote && serverKey.Remote != nil {
		runtime.Outbound = append(runtime.Outbound, trustconfig.OutboundEndpoint{
			Source: "server signer", Endpoint: serverKey.Remote.Endpoint,
		})
	}
	if rt.auditKey.Provider == keydescriptor.ProviderRemote && rt.auditKey.Remote != nil {
		runtime.Outbound = append(runtime.Outbound, trustconfig.OutboundEndpoint{
			Source: "audit signer", Endpoint: rt.auditKey.Remote.Endpoint,
		})
	}
	if rt.cfg.NATS.Enabled {
		for _, endpoint := range rt.cfg.NATS.URLs {
			runtime.Outbound = append(runtime.Outbound, trustconfig.OutboundEndpoint{
				Source: "nats", Endpoint: endpoint,
			})
		}
	}
	if strings.EqualFold(strings.TrimSpace(metastoreKind), "tikv") {
		for _, endpoint := range tikvPDAddresses {
			runtime.Outbound = append(runtime.Outbound, trustconfig.OutboundEndpoint{
				Source: "tikv", Endpoint: "tikv://" + strings.TrimSpace(endpoint),
			})
		}
	}
	if trust != nil {
		runtime.FISCOCryptoMode = string(trust.CryptoMode)
		runtime.FISCOKeyProvider = trust.AccountProvider.Provider
		runtime.FISCOPeerPins = len(trust.Certificates.PinnedPeerCertificateHashes) > 0
		for _, endpoint := range trust.Endpoints {
			runtime.Outbound = append(runtime.Outbound, trustconfig.OutboundEndpoint{
				Source: "fisco-bcos", Endpoint: endpoint,
			})
		}
		if trust.AccountProvider.Provider == "remote" {
			var reference fiscoBCOSRemoteReference
			if err := unmarshalCanonicalJSONReference(trust.AccountProvider.KeyReference, &reference); err != nil {
				return fmt.Errorf("validate FISCO BCOS remote account egress: %w", err)
			}
			runtime.Outbound = append(runtime.Outbound, trustconfig.OutboundEndpoint{
				Source: "fisco-bcos account signer", Endpoint: reference.Endpoint,
			})
		}
	}
	if err := trustconfig.ValidateDeploymentRuntime(
		rt.cfg.RunProfile,
		rt.cfg.DeploymentPolicy,
		runtime,
	); err != nil {
		return fmt.Errorf("deployment policy: %w", err)
	}
	if len(rt.cfg.DeploymentPolicy.Exceptions) > 0 && rt.auditor == nil {
		return fmt.Errorf("deployment policy exceptions require an active security audit writer")
	}
	for _, exception := range rt.cfg.DeploymentPolicy.Exceptions {
		if err := rt.auditRecord(ctx, securityaudit.Draft{
			Action: "deployment.policy.exception",
			Object: exception.ID,
			Result: "accepted",
			Source: "server",
			Context: map[string]string{
				"profile":     trustconfig.NormalizeRunProfile(rt.cfg.RunProfile),
				"control":     exception.Control,
				"approved_by": exception.ApprovedBy,
				"ticket":      exception.Ticket,
				"expires_at":  exception.ExpiresAt,
				"reason":      exception.Reason,
			},
		}); err != nil {
			return fmt.Errorf("audit deployment policy exception %q: %w", exception.ID, err)
		}
	}
	return nil
}
