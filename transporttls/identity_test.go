package transporttls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestHTTPPeerIdentityExposesVerifiedTransportInput(t *testing.T) {
	t.Parallel()
	leaf := &x509.Certificate{
		Raw:          []byte("verified-client-certificate"),
		Subject:      pkix.Name{CommonName: "ingest-client", Organization: []string{"TrustDB operators"}},
		SerialNumber: big.NewInt(42),
		DNSNames:     []string{"client.internal"},
	}
	handler := HTTPPeerIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := PeerIdentityFromContext(r.Context())
		if !ok {
			t.Error("verified peer identity missing from context")
			return
		}
		if identity.CommonName != "ingest-client" || identity.SerialNumber != "2a" || identity.TLSVersion != "TLS1.3" {
			t.Errorf("peer identity = %+v", identity)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://trustdb.test/healthz", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestHTTPPeerIdentityIgnoresUnverifiedPeerCertificates(t *testing.T) {
	t.Parallel()
	handler := HTTPPeerIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := PeerIdentityFromContext(r.Context()); ok {
			t.Error("unverified peer certificate became an identity")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "https://trustdb.test/healthz", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "unverified"}}}}
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestGRPCUnaryInterceptorExposesVerifiedTransportInput(t *testing.T) {
	t.Parallel()
	leaf := &x509.Certificate{Raw: []byte("grpc-client"), Subject: pkix.Name{CommonName: "grpc-client"}, SerialNumber: big.NewInt(7)}
	ctx := peer.NewContext(t.Context(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		Version: tls.VersionTLS12, VerifiedChains: [][]*x509.Certificate{{leaf}},
	}}})
	_, err := UnaryServerInterceptor(ctx, struct{}{}, nil, func(ctx context.Context, _ any) (any, error) {
		identity, ok := PeerIdentityFromContext(ctx)
		if !ok || identity.CommonName != "grpc-client" || identity.TLSVersion != "TLS1.2" {
			t.Fatalf("gRPC peer identity = %+v, ok=%v", identity, ok)
		}
		return struct{}{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
