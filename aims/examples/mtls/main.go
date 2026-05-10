// Package main demonstrates AIMS agent authentication using mTLS with X.509 SVID.
//
// This example shows:
//   - Creating a self-signed X.509 certificate with SPIFFE ID
//   - Using X.509 SVID for authentication
//   - Setting up mTLS server and client
//
// # EXPERIMENTAL
//
// This example implements draft-klrc-aiagent-auth-00 which is subject to change.
//
// Note: This example uses self-signed certificates for demonstration.
// In production, certificates would be issued by SPIRE or another SPIFFE-compliant
// certificate authority.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/aistandardsio/agent-protocols/aims"
)

const (
	trustDomain = "example.com"
	serverAddr  = "localhost:18443"
)

func main() {
	log.Println("=== AIMS mTLS Authentication Demo ===")
	log.Println("This demo shows agent authentication using X.509 SVID over mTLS.")
	log.Println()

	// Step 1: Create CA certificate (simulating SPIFFE trust bundle)
	log.Println("1. Creating CA certificate (SPIFFE trust bundle)...")
	caKey, caCert, err := createCACertificate()
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}
	log.Printf("   CA Subject: %s", caCert.Subject.CommonName)
	log.Println()

	// Step 2: Create server X.509 SVID
	log.Println("2. Creating server X.509 SVID...")
	serverSPIFFE, _ := aims.NewSPIFFEID(trustDomain, "/service/api-server")
	serverKey, serverCert, err := createSVID(caKey, caCert, serverSPIFFE)
	if err != nil {
		log.Fatalf("Failed to create server SVID: %v", err)
	}
	log.Printf("   Server SPIFFE ID: %s", serverSPIFFE.String())
	log.Println()

	// Step 3: Create agent X.509 SVID
	log.Println("3. Creating agent X.509 SVID...")
	agentSPIFFE, _ := aims.NewSPIFFEID(trustDomain, "/agent/calendar-bot")
	agentKey, agentCert, err := createSVID(caKey, caCert, agentSPIFFE)
	if err != nil {
		log.Fatalf("Failed to create agent SVID: %v", err)
	}
	log.Printf("   Agent SPIFFE ID: %s", agentSPIFFE.String())

	// Wrap in X509SVID credential
	agentX509SVID, err := aims.NewX509SVID([]*x509.Certificate{agentCert}, agentKey)
	if err != nil {
		log.Fatalf("Failed to create X509SVID: %v", err)
	}
	log.Printf("   Credential Type: %s", agentX509SVID.Type())
	log.Printf("   Is Expired: %v", agentX509SVID.IsExpired())
	log.Printf("   Expires At: %s", agentX509SVID.ExpiresAt().Format(time.RFC3339))
	log.Println()

	// Step 4: Create CA pool
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Step 5: Start mTLS server
	log.Println("4. Starting mTLS server...")
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
			},
		},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/data", handleData)

	server := &http.Server{
		Addr:              serverAddr,
		Handler:           mux,
		TLSConfig:         serverTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("   Server listening on https://%s", serverAddr)
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	log.Println()

	// Step 6: Create mTLS client with agent SVID
	log.Println("5. Creating mTLS client with agent SVID...")
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{agentCert.Raw},
				PrivateKey:  agentKey,
			},
		},
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
	}
	log.Println("   Client configured with agent X.509 SVID")
	log.Println()

	// Step 7: Make authenticated request
	log.Println("6. Making authenticated mTLS request...")
	resp, err := client.Get(fmt.Sprintf("https://%s/api/v1/data", serverAddr))
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("   Response status: %s", resp.Status)
	log.Printf("   Response body: %s", string(body))
	log.Println()

	// Step 8: Create AgentIdentity
	log.Println("7. Creating AgentIdentity with X.509 SVID...")
	identity := aims.NewAgentIdentity(
		agentSPIFFE,
		agentX509SVID,
		aims.WithAttestation(aims.NewAttestation(aims.AttestationUnix, nil)),
		aims.WithMetadata("transport", "mtls"),
	)
	log.Printf("   SPIFFE ID: %s", identity.SPIFFEID.String())
	log.Printf("   Credential Type: %s", identity.Credential.Type())
	log.Printf("   Is Valid: %v", identity.IsValid())
	log.Printf("   Has Attestation: %v", identity.Attestation != nil)
	log.Println()

	fmt.Println("Demo completed successfully!")
}

func createCACertificate() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "SPIFFE Trust Domain CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func createSVID(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, spiffeID *aims.SPIFFEID) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	spiffeURI, _ := url.Parse(spiffeID.String())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: spiffeID.Name(),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{spiffeURI},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func handleData(w http.ResponseWriter, r *http.Request) {
	// Extract client SPIFFE ID from TLS connection
	var clientSPIFFE string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		for _, uri := range r.TLS.PeerCertificates[0].URIs {
			if uri.Scheme == "spiffe" {
				clientSPIFFE = uri.String()
				break
			}
		}
	}

	response := map[string]any{
		"message":       "Hello from protected resource!",
		"client_spiffe": clientSPIFFE,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
