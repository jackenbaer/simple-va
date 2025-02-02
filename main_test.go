package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func HandleCreateNewCsrTest() (*x509.CertificateRequest, error) {
	// Define a valid request payload
	requestBody := createNewCsrRequest{
		CommonName: "example.com",
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("Status ist not Created: %v", rr.Code)
	}

	// Decode the response body
	var response createNewCsrResponse
	err = json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	csr, err := ParseCSRFromPEM(response.CSR)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func HandleUploadSignedCertTest(certificate *x509.Certificate) error {
	requestBody := UploadSignedCertRequest{
		Certificate: string(CertToPEM(certificate)),
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

func GenerateRootCA(certTemplate *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, privateKey, nil
}

func SignCSR(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csr *x509.CertificateRequest, certTemplate *x509.Certificate) (*x509.Certificate, error) {
	certTemplate.Subject = csr.Subject
	certTemplate.PublicKey = csr.PublicKey

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	return cert, nil
}

func TestCertgen(t *testing.T) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// Basic constraints.
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	rootCert, rootKey, err := GenerateRootCA(rootTemplate)
	if err != nil {
		t.Errorf("Failed to create a root ca for signing. %v", err)
	}
	fmt.Printf("Root CA Certificate:\n%s\n", string(CertToPEM(rootCert)))

	rootKeyPem, err := KeyToPEM(rootKey)
	if err != nil {
		t.Errorf("Failed parse root ca key to pem: %v", err)
	}

	fmt.Printf("Root CA Key:\n%s\n", string(rootKeyPem))

	csr, err := HandleCreateNewCsrTest()
	if err != nil {
		t.Fatalf("Failed to create a new identity. %v", err)
	}
	fmt.Printf("OCSP Signer CSR:\n%s\n", string(CSRToPEM(csr)))

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		IsCA:         false,
	}
	ocspSignerCert, err := SignCSR(rootCert, rootKey, csr, certTemplate)
	if err != nil {
		t.Fatalf("Failed to create a new identity. %v", err)
	}
	fmt.Printf("OCSP Signer Certificate:\n%s\n", string(CertToPEM(ocspSignerCert)))

	err = HandleUploadSignedCertTest(ocspSignerCert)
	if err != nil {
		t.Fatalf("Failed to upload cert. %v", err)
	}
	certs, err := HandleListCertsTest()
	if err != nil {
		t.Fatalf("Failed to list certificates. %v", err)
	}
	fmt.Printf("Listed certificates: %v\n", certs)
}

func TestMain(m *testing.M) {
	Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

	identity = &Identity{FolderPath: "./identityFolder/"}

	err := identity.getOrCreatePrivateKey()
	if err != nil {
		fmt.Printf("Failed to initialize identity: %v", err)
		os.Exit(1)
	}

	code := m.Run()

	os.Exit(code)
}
