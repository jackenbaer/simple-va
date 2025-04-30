package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/http"
	"runtime/debug"
	"simple-va/storage"
	"time"
)

type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue
	SubjectPublicKey asn1.BitString
}

type RemoveRevokeCertRequest struct {
	IssuerKeyHash string `json:"issuer_key_hash"`
	SerialNumber  string `json:"serial_number"`
}

// HandleRemoveRevokedCert
// @Summary      Remove a revoked certificate from the list
// @Description  Remove a revoked certificate from the list
// @Tags         RevokedCertListAction
// @Produce      application/json
// @Success      200  {string}  string  "Certificate successfully removed"
// @Router       /v1/removerevokedcert [post]
func HandleRemoveRevokedCert(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	//Validation
	var req RemoveRevokeCertRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	exists, err := CertStatus.Remove(req.IssuerKeyHash, req.SerialNumber)
	if err != nil {
		Logger.Error("failed to revoke certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to revoke Certificate", http.StatusInternalServerError)
	}
	if !exists {
		Logger.Info("Certificate did not exists")
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate successfully revoked"))

}

type ListRevokedCertsResponse struct {
	RevokedCerts map[string]map[string]storage.OCSPEntry `json:"revoked_certs"`
}

// HandleLisRevokedCerts
// @Summary      List all revoked certificates
// @Description  Retrieves all revoked certificates
// @Tags         RevokedCertListAction
// @Produce      application/json
// @Success      200  {object}  ListRevokedCertsResponse
// @Router       /v1/listrevokedcerts [get]
func HandleListRevokedCerts(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
	if !validateMethod(w, r, http.MethodGet) {
		return
	}

	writeJSONResponse(w, http.StatusOK, ListRevokedCertsResponse{RevokedCerts: CertStatus.List()})
}

type AddRevokeCertRequest struct {
	IssuerKeyHash    string    `json:"issuer_key_hash"`
	SerialNumber     string    `json:"serial_number"`
	RevocationReason string    `json:"revocation_reason"`
	RevocationDate   time.Time `json:"revocation_date"`
	ExpirationDate   time.Time `json:"expiration_date"`
}

// HandleAddRevokedCert
// @Summary      Add a revoked certificate
// @Description  Marks a certificate as revoked using issuer key hash, serial number, and revocation metadata.
// @Tags         RevokedCertListAction
// @Accept       application/json
// @Produce      application/json
// @Param        cert body AddRevokeCertRequest true "Certificate revocation details"
// @Success      200  {string}  string  "Certificate successfully revoked"
// @Failure      400  {string}  string  "Invalid request"
// @Failure      500  {string}  string  "Failed to revoke certificate"
// @Router       /v1/revokecert [post]

func HandleAddRevokedCert(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	//Validation
	var req AddRevokeCertRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	ocsp := storage.OCSPEntry{
		ExpirationDate:   req.ExpirationDate,
		RevocationDate:   req.RevocationDate,
		RevocationReason: req.RevocationReason,
		SerialNumber:     req.SerialNumber,
	}

	err := CertStatus.AddEntry(req.IssuerKeyHash, ocsp)
	if err != nil {
		Logger.Error("failed to revoke certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to revoke Certificate", http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate successfully revoked"))

}

type ListCertsResponse struct {
	Certificates []string `json:"certificates"`
}

// HandleListCerts
// @Summary      List all OCSP certificates
// @Description  Retrieves all OCSP responder certificates stored in the manager, returned as PEM-encoded strings.
// @Produce      application/json
// @Success      200  {object}  ListCertsResponse
// @Router       /v1/listcerts [get]
func HandleListCerts(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
	if !validateMethod(w, r, http.MethodGet) {
		return
	}

	certs := []string{}
	for _, v := range ocspCertManager.ListOCSPCerts() {
		certs = append(certs, v.ToPEM())
	}

	writeJSONResponse(w, http.StatusOK, ListCertsResponse{Certificates: certs})
}

type UploadSignedCertRequest struct {
	SignedCert string `json:"signed_certificate"`

	IssuerCert string `json:"issuer_certificate"`
}

// HandleUploadSignedCert
// @Summary      Upload a signed OCSP responder certificate
// @Description  Uploads a signed OCSP responder certificate along with its issuer certificate (both PEM-encoded).
// @Accept       application/json
// @Produce      text/plain
// @Param        payload  body  UploadSignedCertRequest  true  "Signed OCSP cert and issuer cert in PEM format"
// @Success      200      {string}  string  "Certificate uploaded successfully"
// @Failure      400      {string}  string  "Bad request (e.g. missing fields)"
// @Failure      500      {string}  string  "Failed to upload certificate"
// @Router       /v1/uploadsignedcert [post]
func HandleUploadSignedCert(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
	if !validateMethod(w, r, http.MethodPost) {
		return
	}

	//Validation
	var req UploadSignedCertRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	ocspCert, err := PemToCert([]byte(req.SignedCert))
	if err != nil {
		Logger.Error("failed to parse ocsp certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
	}
	issuerCert, err := PemToCert([]byte(req.IssuerCert))
	if err != nil {
		Logger.Error("failed to parse issuer certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
	}

	responder := OCSPResponder{
		OcspCert:   ocspCert,
		IssuerCert: issuerCert,
	}

	hashstring, err := responder.ComputeIssuerKeyHash()
	if err != nil {
		Logger.Error("failed to parse issuer certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to upload certificate", http.StatusInternalServerError)
		return
	}
	fmt.Printf("hhhash: %s\n", hashstring)

	ocspCertManager.AddResponder(responder)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate uploaded successfully"))
}

type RemoveResponderRequest struct {
	IssuerCert string `json:"issuer_certificate"`
	OcspCert   string `json:"ocsp_certificate"`
}

// HandleRemoveResponder
// @Summary      Remove an OCSP responder
// @Description  Removes an OCSP responder identified by its issuer certificate and responder certificate (both PEM-encoded).
// @Accept       application/json
// @Produce      text/plain
// @Param        payload  body  RemoveResponderRequest  true  "Issuer cert and OCSP cert in PEM format"
// @Success      200      {string}  string  "Certificate successfully removed"
// @Failure      400      {string}  string  "Bad request (e.g. invalid JSON)"
// @Failure      500      {string}  string  "Failed to remove certificate"
// @Router       /v1/removeresponder [post]
func HandleRemoveResponder(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
	if !validateMethod(w, r, http.MethodPost) {
		return
	}
	//Validation
	var req RemoveResponderRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	caCert, err := PemToCert([]byte(req.IssuerCert))
	if err != nil {
		Logger.Error("failed to parse issuer certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}

	ocspCert, err := PemToCert([]byte(req.OcspCert))
	if err != nil {
		Logger.Error("failed to parse ocsp certificate",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}

	o := OCSPResponder{OcspCert: ocspCert, IssuerCert: caCert}
	hash, err := o.ComputeIssuerKeyHash()
	if err != nil {
		Logger.Error("failed to calculate hash",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}
	ocspCertManager.RemoveResponder(hash)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate successfully removed"))

}

type createNewCsrRequest struct {
	CommonName string `json:"common_name"`
}

type createNewCsrResponse struct {
	CSR string `json:"csr"`
}

// HandleCreateNewCsr
// @Summary      Create a new Certificate Signing Request (CSR)
// @Description  Generates a new ECDSA CSR for the given common name.
// @Accept       application/json
// @Produce      application/json
// @Param        payload  body  createNewCsrRequest  true  "Common name for the CSR"
// @Success      200      {object}  createNewCsrResponse
// @Failure      400      {string}  string  "CommonName is required or CSR generation failed"
// @Router       /v1/createnewcsr [post]
func HandleCreateNewCsr(w http.ResponseWriter, r *http.Request) {
	if !authorize(w, r) {
		return
	}
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
			"stack", string(debug.Stack()),
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
