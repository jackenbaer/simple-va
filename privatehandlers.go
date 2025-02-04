package main

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
)

// Unified method validator
func validateMethod(w http.ResponseWriter, r *http.Request, expectedMethod string) bool {
	if r.Method != expectedMethod {
		Logger.Debug("Rejected request due to invalid HTTP method",
			"received_method", r.Method,
			"expected_method", expectedMethod,
			"endpoint", r.URL.Path,
		)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// Unified request decoder
func decodeJSONRequest(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		Logger.Warn("Invalid JSON body",
			"error", err,
			"status", http.StatusBadRequest,
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
		)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

// Unified response writer
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		Logger.Error("Failed to encode response",
			"error", err,
		)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

type ListCertsResponse struct {
	Certificates []string `json:"certificates"`
}

type UploadSignedCertRequest struct {
	SignedCert string `json:"signed_certificate"`
	IssuerCert string `json:"issuer_certificate`
}

func HandleListCerts(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodGet) {
		return
	}
	certs := identity.ListOCSPCerts()
	writeJSONResponse(w, http.StatusOK, ListCertsResponse{Certificates: certs})
}

type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue // Wir benötigen hier den AlgorithmIdentifier nicht weiter.
	SubjectPublicKey asn1.BitString
}

func computeIssuerKeyHash(issuerCert *x509.Certificate) (string, error) {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(issuerCert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return "", fmt.Errorf("failed to unmarshal subjectPublicKeyInfo: %w", err)
	}
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

func HandleUploadSignedCert(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	//Validation
	var req UploadSignedCertRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	err := identity.AddOCSPCert(req.SignedCert)
	if err != nil {
		Logger.Error("Failed to add OCSP cert",
			"error", err,
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
	}
	ocspCert, err := PemToCert([]byte(req.SignedCert))
	if err != nil {
		Logger.Error("failed to parse ocsp certificate",
			"error", err,
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
	}

	issuerCert, err := PemToCert([]byte(req.IssuerCert))
	if err != nil {
		Logger.Error("failed to parse issuer certificate",
			"error", err,
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
	}

	hashstring, err := computeIssuerKeyHash(issuerCert)
	if err != nil {
		Logger.Error("failed to parse issuer certificate",
			"error", err,
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
	}
	fmt.Printf("hhhash: %s\n", hashstring)

	responderMap[hashstring] = OCSPResponder{
		OcspCert:   ocspCert,
		IssuerCert: issuerCert,
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate uploaded successfully"))
}

type createNewCsrRequest struct {
	CommonName string `json:"common_name"`
}

type createNewCsrResponse struct {
	CSR string `json:"csr"`
}

func HandleCreateNewCsr(w http.ResponseWriter, r *http.Request) {
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	//Validation
	var req createNewCsrRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	// Validate the request (ensure CommonName is not empty)
	if req.CommonName == "" {
		Logger.Warn("Invalid JSON body: Common name cannot be empty",
			"status", http.StatusBadRequest,
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
		)

		http.Error(w, "CommonName is required", http.StatusBadRequest)
		return
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{"Example Organization"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrBytes, err := identity.CreateCsr(csrTemplate)
	if err != nil {
		Logger.Error("CSR generation Failed",
			"error", err,
		)

		http.Error(w, "CSR generation Failed.", http.StatusBadRequest)
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	writeJSONResponse(w, http.StatusOK, createNewCsrResponse{CSR: string(csrPEM)})
}
