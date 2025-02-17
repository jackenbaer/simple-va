package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/http"
)

type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue // Wir benötigen hier den AlgorithmIdentifier nicht weiter.
	SubjectPublicKey asn1.BitString
}

type ListCertsResponse struct {
	Certificates []string `json:"certificates"`
}

func HandleListCerts(w http.ResponseWriter, r *http.Request) {
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

func HandleUploadSignedCert(w http.ResponseWriter, r *http.Request) {
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

	responder := OCSPResponder{
		OcspCert:   ocspCert,
		IssuerCert: issuerCert,
	}

	hashstring, err := responder.ComputeIssuerKeyHash()
	if err != nil {
		Logger.Error("failed to parse issuer certificate",
			"error", err,
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
	Crl        string `json:"crl"`
}

func HandleRemoveResponder(w http.ResponseWriter, r *http.Request) {
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
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}

	ocspCert, err := PemToCert([]byte(req.OcspCert))
	if err != nil {
		Logger.Error("failed to parse ocsp certificate",
			"error", err,
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}

	crl, err := PemToCrl(req.Crl)
	if err != nil {
		Logger.Error("failed to parse crl",
			"error", err,
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}

	isrevoked := false
	for _, revoked := range crl.RevokedCertificates {
		// Compare the serial numbers.
		if revoked.SerialNumber.Cmp(ocspCert.SerialNumber) == 0 {
			isrevoked = true
		}
	}
	if !isrevoked {
		Logger.Error("OCSP certificate is not revoked in crl",
			"error", err,
		)
		http.Error(w, "Failed to remove certificate", http.StatusInternalServerError)
		return
	}
	o := OCSPResponder{OcspCert: ocspCert, IssuerCert: caCert}
	hash, err := o.ComputeIssuerKeyHash()
	if err != nil {
		Logger.Error("failed to calculate hash",
			"error", err,
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
