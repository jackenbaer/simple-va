package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func HandleRemoveRevokedCertTest(issuerKeyHash string, serialNumber string) error {
	requestBody := RemoveRevokeCertRequest{
		IssuerKeyHash: issuerKeyHash,
		SerialNumber:  serialNumber,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/v1.0.0/removerevokedcert", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleRemoveRevokedCert)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return fmt.Errorf("Status ist not OK: %v", rr.Code)
	}
	return nil
}

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

func HandleAddRevokedCertTest(issuerKeyHash string, serialNumber string, expirationDate time.Time) error {
	requestBody := AddRevokeCertRequest{
		IssuerKeyHash:    issuerKeyHash,
		SerialNumber:     serialNumber,
		ExpirationDate:   expirationDate,
		RevocationReason: "1",
		RevocationDate:   time.Now(),
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/v1.0.0/addrevokedcert", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleAddRevokedCert)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return fmt.Errorf("Status ist not OK: %v", rr.Code)
	}
	return nil
}

func HandleRemoveResponderTest(certToRevoke *x509.Certificate, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	requestBody := RemoveResponderRequest{
		IssuerCert: string(CertToPEM(caCert)),
		OcspCert:   string(CertToPEM(certToRevoke)),
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/v1.0.0/removeresponder", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleRemoveResponder)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return fmt.Errorf("Status ist not OK: %v", rr.Code)
	}
	return nil
}

func HandleUploadSignedCertTest(certificate *x509.Certificate, issuer *x509.Certificate) error {
	requestBody := UploadSignedCertRequest{
		SignedCert: string(CertToPEM(certificate)),
		IssuerCert: string(CertToPEM(issuer)),
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/v1.0.0/createnewidentity", bytes.NewReader(bodyBytes))
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
	req := httptest.NewRequest(http.MethodGet, "/v1.0.0/listcerts", nil)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleListResponderCerts)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return []string{}, fmt.Errorf("Status ist not OK: %v", rr.Code)
	}

	var response ListResponderCertsResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return []string{}, err
	}
	return response.Certificates, nil
}

func ApiKeyAuhTest(apiKey string) int {
	req := httptest.NewRequest(http.MethodGet, "/v1.0.0/listcerts", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-API-Key", apiKey)

	rr := httptest.NewRecorder()

	wrapped := Middleware(http.MethodGet, HandleListResponderCerts)
	handler := http.HandlerFunc(wrapped)
	handler.ServeHTTP(rr, req)

	return rr.Code
}

func HandleListRevokedCertsTest() (map[string]map[string]OCSPEntry, error) {
	req := httptest.NewRequest(http.MethodGet, "/v1.0.0/listrevokedcerts", nil)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleListRevokedCerts)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return nil, fmt.Errorf("Status ist not OK: %v", rr.Code)
	}

	var response ListRevokedCertsResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.RevokedCerts, nil
}

func GenerateRootCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
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

func createLeafCert(rootCert *x509.Certificate, rootKey crypto.PrivateKey) (*x509.Certificate, crypto.Signer, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	leafCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Leaf Certificate",
			Organization: []string{"Example Org"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:  []string{"http://localhost:8081/ocsp"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, leafCertTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	signedLeafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	return signedLeafCert, leafKey, nil
}

func SignCSR(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		IsCA:         false,
	}
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

func performOCSPTestRequest(leafCert, rootCert *x509.Certificate) (int, error) {
	ocspReqDER, err := ocsp.CreateRequest(leafCert, rootCert, nil)
	if err != nil {
		return -1, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	server := httptest.NewServer(http.HandlerFunc(HandleOcsp))
	defer server.Close()

	resp, err := http.Post(server.URL, "application/ocsp-request", bytes.NewReader(ocspReqDER))
	if err != nil {
		return -1, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "application/ocsp-response" {
		return -1, fmt.Errorf("unexpected content type: %s", ct)
	}

	ocspRespDER, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(ocspRespDER, nil)
	if err != nil {
		return -1, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	return ocspResp.Status, nil
}

func TestCertgen(t *testing.T) {
	// Generate a root CA
	rootCert, rootKey, err := GenerateRootCA()
	if err != nil {
		t.Errorf("Failed to create a root ca for signing. %v", err)
	}
	fmt.Printf("Root CA Certificate:\n%s\n", string(CertToPEM(rootCert)))

	rootKeyPem, err := KeyToPEM(rootKey)
	if err != nil {
		t.Errorf("Failed parse root ca key to pem: %v", err)
	}
	fmt.Printf("Root CA Key:\n%s\n", string(rootKeyPem))

	// Generate a CSR in simple-va
	csr, err := HandleCreateNewCsrTest()
	if err != nil {
		t.Fatalf("Failed to create a new identity. %v", err)
	}
	fmt.Printf("OCSP Signer CSR:\n%s\n", string(CSRToPEM(csr)))

	// Sign CSR with root CA
	ocspSignerCert, err := SignCSR(rootCert, rootKey, csr)
	if err != nil {
		t.Fatalf("Failed to create a new identity. %v", err)
	}
	fmt.Printf("OCSP Signer Certificate:\n%s\n", string(CertToPEM(ocspSignerCert)))

	// Upload signed CSR to simple-va
	err = HandleUploadSignedCertTest(ocspSignerCert, rootCert)
	if err != nil {
		t.Fatalf("Failed to upload cert. %v", err)
	}

	// Create leaf cert for revocation tests
	leafCert, _, err := createLeafCert(rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create leaf cert. %v", err)
	}

	// Create an OCSP request using the leaf and issuer certificates.
	status, err := performOCSPTestRequest(leafCert, rootCert)
	if err != nil {
		t.Fatalf("Failed to create ocsp request. %v", err)
	}
	if status != 0 {
		t.Fatalf("Expected OCSP state good ")
	}

	// Now revoke the cert
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(rootCert.RawSubjectPublicKeyInfo, &spki); err != nil {
		fmt.Errorf("failed to unmarshal subjectPublicKeyInfo: %w", err)
	}
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	issuerKHash := hex.EncodeToString(hash[:])
	err = HandleAddRevokedCertTest(issuerKHash, leafCert.SerialNumber.String(), leafCert.NotAfter)
	if err != nil {
		t.Fatalf("Failed to revoke cert. %v", err)
	}

	// Create an OCSP request using the leaf and issuer certificates.
	status, err = performOCSPTestRequest(leafCert, rootCert)
	if err != nil {
		t.Fatalf("Failed to create ocsp request. %v", err)
	}
	if status != 1 {
		t.Fatalf("Expected OCSP state revoked ")
	}

	//Not undo the revocation
	err = HandleRemoveRevokedCertTest(issuerKHash, leafCert.SerialNumber.String())
	if err != nil {
		t.Fatalf("Failed to revoke cert. %v", err)
	}

	// Create an OCSP request using the leaf and issuer certificates.
	status, err = performOCSPTestRequest(leafCert, rootCert)
	if err != nil {
		t.Fatalf("Failed to create ocsp request. %v", err)
	}
	if status != 0 {
		t.Fatalf("Expected OCSP state good ")
	}

	// Remove the Responder
	fmt.Println("Removing ocsp responder ...")
	err = HandleRemoveResponderTest(ocspSignerCert, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to upload cert. %v", err)
	}
	certs, err := HandleListCertsTest()
	if err != nil {
		t.Fatalf("Failed to list certificates. %v", err)
	}
	fmt.Printf("Listed certificates: %v\n", certs)

	//valid api key
	code := ApiKeyAuhTest("123")
	if code != 200 {
		t.Fatalf("Failed to authenticate with correct api key")
	}
	code = ApiKeyAuhTest("wrong")
	if code != 401 {
		t.Fatalf("Wrong apikey was able to authenticate")
	}
	//invalid api key
}

func OCSPCerts() ([]string, error) {
	req := httptest.NewRequest(http.MethodGet, "/listcerts", nil)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(HandleListResponderCerts)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		return []string{}, fmt.Errorf("Status ist not OK: %v", rr.Code)
	}

	var response ListResponderCertsResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		return []string{}, err
	}
	return response.Certificates, nil
}

func WriteTempFile(prefix string, content string, logger func(msg string, keyvals ...interface{})) (string, func(), error) {
	tmpfile, err := os.CreateTemp("", prefix+"*")
	if err != nil {
		logger("failed to create temp file", "error", err)
		return "", nil, err
	}

	if _, err := tmpfile.WriteString(content); err != nil {
		logger("failed to write to temp file", "error", err)
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return "", nil, err
	}

	if err := tmpfile.Close(); err != nil {
		logger("failed to close temp file", "error", err)
		os.Remove(tmpfile.Name())
		return "", nil, err
	}

	cleanup := func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			logger("failed to remove temp file", "error", err)
		}
	}

	return tmpfile.Name(), cleanup, nil
}
func TestMain(m *testing.M) {

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger = slog.New(handler)
	Logger.Info("#########################  STARTING  #########################", "version", Version, "commit", Commit, "build_time", BuildTime)

	// Create temporary /var/lib like folder
	varLibFolder, err := os.MkdirTemp("", "simple-va-*")
	if err != nil {
		Logger.Error("Failed to create temp dir", "error", err)
	}
	defer func() {
		if err := os.RemoveAll(varLibFolder); err != nil {
			Logger.Error("Failed to remove temp dir", "error", err)
		}
	}()

	apiKeyList := `
	{
 "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "123"
}`

	apiKeyListPath, cleanup, err := WriteTempFile("apikey-", apiKeyList, Logger.Error)
	if err != nil {
		// Handle error accordingly
		return
	}
	defer cleanup()

	Config = &Configuration{
		HostnamePrivateApi:      "localhost:8080",
		HostnamePublicApi:       "localhost:8081",
		PrivateKeyPath:          filepath.Join(varLibFolder, "priv.pem"),
		CertsFolderPath:         filepath.Join(varLibFolder, "certs"),
		CertStatusPath:          filepath.Join(varLibFolder, "statuslist.json"),
		HashedApiKeysPath:       apiKeyListPath,
		PrivateEndpointKeyPath:  "",
		PrivateEndpointCertPath: "",
	}

	err = os.Mkdir(Config.CertsFolderPath, 0o755) // system-tmp, automatisch eindeutig
	if err != nil {
		if os.IsExist(err) {
			Logger.Warn("cannot create cert dir", "error", err)
		} else {
			Logger.Error("Unexpected error while creating directory:", "error", err)
			os.Exit(1)
		}
	}

	ApiKeys = &ApiKeyStore{}
	if Config.HashedApiKeysPath != "" {
		err = ApiKeys.LoadFromFile(Config.HashedApiKeysPath)
		if err != nil {
			Logger.Error("Loading Api Key list failed", "error", err, "stack", string(debug.Stack()))
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

	CertStatus = &CertState{CertStatusPath: Config.CertStatusPath}
	err = CertStatus.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}
	code := m.Run()
	Logger.Info("Executed")
	os.Exit(code)
}
