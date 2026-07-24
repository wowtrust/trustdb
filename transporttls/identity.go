package transporttls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerIdentity is an authenticated transport identity input for future RBAC
// and audit layers. It does not grant authorization and is unrelated to the
// tenant/client/key identity inside signed proof material.
type PeerIdentity struct {
	Subject           string
	CommonName        string
	SerialNumber      string
	SHA256Fingerprint string
	DNSNames          []string
	EmailAddresses    []string
	URIs              []string
	TLSVersion        string
}

type peerIdentityContextKey struct{}

// PeerIdentityFromContext returns a verified mTLS peer identity when one was
// presented. TLS without a client certificate intentionally returns false.
func PeerIdentityFromContext(ctx context.Context) (PeerIdentity, bool) {
	identity, ok := ctx.Value(peerIdentityContextKey{}).(PeerIdentity)
	return identity, ok
}

func identityFromState(state tls.ConnectionState) (PeerIdentity, bool) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return PeerIdentity{}, false
	}
	return identityFromCertificate(state.VerifiedChains[0][0], state.Version), true
}

func identityFromCertificate(cert *x509.Certificate, version uint16) PeerIdentity {
	fingerprint := sha256.Sum256(cert.Raw)
	identity := PeerIdentity{
		Subject:           cert.Subject.String(),
		CommonName:        cert.Subject.CommonName,
		SerialNumber:      cert.SerialNumber.Text(16),
		SHA256Fingerprint: hex.EncodeToString(fingerprint[:]),
		DNSNames:          append([]string(nil), cert.DNSNames...),
		EmailAddresses:    append([]string(nil), cert.EmailAddresses...),
		TLSVersion:        VersionName(version),
	}
	for _, uri := range cert.URIs {
		identity.URIs = append(identity.URIs, uri.String())
	}
	return identity
}

// HTTPPeerIdentity adds verified client-certificate identity to the request
// context without changing authorization behavior.
func HTTPPeerIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			if identity, ok := identityFromState(*r.TLS); ok {
				r = r.WithContext(context.WithValue(r.Context(), peerIdentityContextKey{}, identity))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// UnaryServerInterceptor exposes verified client certificate identity to gRPC
// handlers through PeerIdentityFromContext.
func UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(contextWithGRPCPeerIdentity(ctx), req)
}

// StreamServerInterceptor exposes the same identity for streaming RPCs.
func StreamServerInterceptor(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &identityServerStream{ServerStream: stream, ctx: contextWithGRPCPeerIdentity(stream.Context())})
}

func contextWithGRPCPeerIdentity(ctx context.Context) context.Context {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return ctx
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		if ptr, ptrOK := p.AuthInfo.(*credentials.TLSInfo); ptrOK && ptr != nil {
			tlsInfo = *ptr
			ok = true
		}
	}
	if !ok {
		return ctx
	}
	identity, ok := identityFromState(tlsInfo.State)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, peerIdentityContextKey{}, identity)
}

type identityServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *identityServerStream) Context() context.Context { return s.ctx }
