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
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"simple-va/security"
	"simple-va/storage"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func setupPrvHandler() *PrivateHTTPHandler {
	apiKeyStore := security.NewAPIKeyStore(map[string]string{
		"a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "API key is 123",
	})
	return &PrivateHTTPHandler{apiKeyStore: apiKeyStore}
}

func HandleCreateNewCsrTest() (*x509.CertificateRequest, error) {
	prvHandler := setupPrvHandler()
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
	req.Header.Add("X-API-Key", "123")

	// Create a ResponseRecorder to capture the response
	rr := httptest.NewRecorder()

	// Call the handler
	handler := http.HandlerFunc(prvHandler.HandleCreateNewCsr)
	handler.ServeHTTP(rr, req)

	// Check the status code
	if rr.Code != http.StatusOK {
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

func HandleRemoveResponderTest(certToRevoke *x509.Certificate, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	prvHandler := setupPrvHandler()
	requestBody := RemoveResponderRequest{
		IssuerCert: string(CertToPEM(caCert)),
		OcspCert:   string(CertToPEM(certToRevoke)),
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/removeresponder", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-API-Key", "123")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(prvHandler.HandleRemoveResponder)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return fmt.Errorf("Status ist not OK: %v", rr.Code)
	}
	return nil
}

func HandleUploadSignedCertTest(certificate *x509.Certificate, issuer *x509.Certificate) error {
	prvHandler := setupPrvHandler()
	requestBody := UploadSignedCertRequest{
		SignedCert: string(CertToPEM(certificate)),
		IssuerCert: string(CertToPEM(issuer)),
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/createnewidentity", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-API-Key", "123")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(prvHandler.HandleUploadSignedCert)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return fmt.Errorf("Status ist not OK: %v", rr.Code)
	}
	return nil
}

func HandleListCertsTest() ([]string, error) {
	prvHandler := setupPrvHandler()
	req := httptest.NewRequest(http.MethodGet, "/listcerts", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-API-Key", "123")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(prvHandler.HandleListCerts)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
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

	err = HandleUploadSignedCertTest(ocspSignerCert, rootCert)
	if err != nil {
		t.Fatalf("Failed to upload cert. %v", err)
	}
	certs, err := HandleListCertsTest()
	if err != nil {
		t.Fatalf("Failed to list certificates. %v", err)
	}
	fmt.Printf("Listed certificates: %v\n", certs)

	//OCSP Testing
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	leafCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Leaf Certificate",
			Organization: []string{"Example Org"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Set the OCSP endpoint URL:
		OCSPServer: []string{"http://localhost:8081/ocsp"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leafCertTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	// Parse the DER-encoded certificate into an *x509.Certificate.
	signedLeafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse signed certificate: %v", err)
	}
	fmt.Printf("Leaf Certificate:\n%s\n", CertToPEM(signedLeafCert))
	ocspReqDER, err := ocsp.CreateRequest(signedLeafCert, rootCert, nil)
	if err != nil {
		t.Fatalf("failed to create OCSP request: %v", err)
	}
	fmt.Printf("OCSP Request (DER in hex):\n%x\n", ocspReqDER)

	// Get the responder URL from the leaf certificate.
	if len(signedLeafCert.OCSPServer) == 0 {
		t.Fatalf("no OCSP server URL in leaf certificate")
	}
	ocspURL := signedLeafCert.OCSPServer[0]
	fmt.Printf("OCSP Responder URL: %s\n", ocspURL)

	server := httptest.NewServer(http.HandlerFunc(HandleOcsp))
	defer server.Close()

	// Create an OCSP request using the leaf and issuer certificates.
	ocspReqDER, err = ocsp.CreateRequest(signedLeafCert, rootCert, nil)
	if err != nil {
		t.Fatalf("failed to create OCSP request: %v", err)
	}

	// Send the OCSP request to our test server.
	resp, err := http.Post(server.URL, "application/ocsp-request", bytes.NewReader(ocspReqDER))
	if err != nil {
		t.Fatalf("failed to send OCSP request: %v", err)
	}
	defer resp.Body.Close()

	// Verify the Content-Type of the response.
	if ct := resp.Header.Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("unexpected content type: %s", ct)
	}

	// Read the binary OCSP response.
	ocspRespDER, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read OCSP response: %v", err)
	}
	ocspResp, err := ocsp.ParseResponse(ocspRespDER, nil)
	if err != nil {
		t.Fatalf("failed to parse OCSP response: %v", err)
	}

	// Log the raw binary response in hexadecimal.
	fmt.Println("OCSP Response Status:", ocspResp.Status)
	fmt.Println("This Update:", ocspResp.ThisUpdate)
	fmt.Println("Next Update:", ocspResp.NextUpdate)
	fmt.Println("Produced At:", ocspResp.ProducedAt)

	fmt.Println("Removing ocsp responder ...")
	err = HandleRemoveResponderTest(ocspSignerCert, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to upload cert. %v", err)
	}
	certs, err = HandleListCertsTest()
	if err != nil {
		t.Fatalf("Failed to list certificates. %v", err)
	}
	fmt.Printf("Listed certificates: %v\n", certs)
}

func OCSPCerts() ([]string, error) {
	prvHandler := setupPrvHandler()
	req := httptest.NewRequest(http.MethodGet, "/listcerts", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-API-Key", "123")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(prvHandler.HandleListCerts)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return []string{}, fmt.Errorf("Status ist not OK: %v", rr.Code)
	}

	var response ListCertsResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return []string{}, err
	}
	return response.Certificates, nil
}

func TestMain(m *testing.M) {

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger = slog.New(handler)
	Logger.Info("#########################  STARTING  #########################", "version", Version, "commit", Commit, "build_time", BuildTime)

	tmpDir := "simple-va"
	err := os.Mkdir(tmpDir, 0755)
	if err != nil {
		if os.IsExist(err) {
			Logger.Warn("Directory already exists (expected error):", "error", err)
		} else {
			Logger.Error("Unexpected error while creating directory:", "error", err)
		}
	} else {
		Logger.Warn("Directory was created successfully")
		defer os.RemoveAll(tmpDir)
	}

	Config = Configuration{
		HostnamePrivateApi: "localhost:8080",
		HostnamePublicApi:  "localhost:8081",
		PrivateKeyPath:     filepath.Join(tmpDir, "priv.pem"),
		CertsFolderPath:    filepath.Join(tmpDir, "certs"),
		CertStatusPath:     filepath.Join(tmpDir, "statuslist.json"),
		HashedApiKeysPath:  "./testdata/security/hashed_api_keys.json",
	}

	err = os.Mkdir(Config.CertsFolderPath, 0o755) // system-tmp, automatisch eindeutig
	if err != nil {
		if os.IsExist(err) {
			Logger.Error("cannot create cert dir", "error", err)
		} else {
			Logger.Error("Unexpected error while creating directory:", "error", err)
			os.Exit(1)
		}
	}

	identity = &Identity{PrivateKeyPath: Config.PrivateKeyPath}
	err = identity.Init()
	if err != nil {
		Logger.Error("Failed to init identity", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	ocspCertManager = &OCSPCertManager{certsFolderPath: Config.CertsFolderPath, responders: make(map[string]OCSPResponder)}
	err = ocspCertManager.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	CertStatus = &storage.CertStatus{CertStatusPath: Config.CertStatusPath}
	err = CertStatus.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}
	code := m.Run()

	go StartPublicListener()

	os.Exit(code)
}
