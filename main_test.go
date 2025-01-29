package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func HandleCreateNewCsrTest() (string, error) {
	// Define a valid request payload
	requestBody := createNewCsrRequest{
		CommonName: "example.com",
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	// Create a new HTTP request
	req := httptest.NewRequest(http.MethodPost, "/createnewidentity", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// Create a ResponseRecorder to capture the response
	rr := httptest.NewRecorder()

	// Call the handler
	handler := http.HandlerFunc(HandleCreateNewCsr)
	handler.ServeHTTP(rr, req)

	// Check the status code
	if rr.Code != http.StatusCreated {
		return "", fmt.Errorf("Status ist not Created: %v", rr.Code)
	}

	// Decode the response body
	var response createNewCsrResponse
	err = json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return "", err
	}

	// Ensure the CSR field is not empty
	if response.CSR == "" {
		return "", err
	}
	return response.CSR, nil
}
func HandleUploadSignedCertTest(certificate string) error {
	requestBody := UploadSignedCertRequest{
		Certificate: certificate,
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/createnewidentity", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleUploadSignedCert)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return fmt.Errorf("Status ist not OK: %v", rr.Code)
	}
	return nil
}

func HandleListCertsTest() ([]string, error) {
	req := httptest.NewRequest(http.MethodGet, "/listcerts", nil)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleListCerts)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		return []string{}, fmt.Errorf("Status ist not OK: %v", rr.Code)
	}

	var response ListCertsResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return []string{}, err
	}
	return response.Certificates, nil
}

func TestCertgen(t *testing.T) {
	identity = &Identity{}

	err := identity.GetOrCreatePrivateKey(".")
	if err != nil {
		t.Fatalf("Failed to initialize identity: %v", err)
	}

	csrPem, err := HandleCreateNewCsrTest()
	if err != nil {
		t.Fatalf("Failed to create a new identity. %v", err)
	}
	fmt.Printf("CSR:\n %s", csrPem)
	certPem, keyPem, err := GenerateRootCA()
	if err != nil {
		t.Errorf("Failed to create a root ca for signing. %v", err)
	}
	fmt.Printf("Root Cert:\n %s", certPem)
	fmt.Printf("Root Key:\n %s", keyPem)

	csrCertPEM, err := SignCSR(certPem, keyPem, []byte(csrPem))
	if err != nil {
		t.Fatalf("Failed to create a new identity. %v", err)
	}
	fmt.Printf("Signed Cert:\n %s", csrCertPEM)

	err = HandleUploadSignedCertTest(string(csrCertPEM))
	if err != nil {
		t.Fatalf("Failed to upload cert. %v", err)
	}
	certs, err := HandleListCertsTest()
	if err != nil {
		t.Fatalf("Failed to list certificates. %v", err)
	}
	fmt.Printf("Listed certificates: %v", certs)
}

func GenerateRootCA() ([]byte, []byte, error) {
	// Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create a self-signed certificate template
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// Create the self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the certificate and private key in PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	return certPEM, keyPEM, nil
}

func SignCSR(caCertPEM, caKeyPEM, csrPEM []byte) ([]byte, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to parse CA private key")
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to parse CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		IsCA:         false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return certPEM, nil
}
