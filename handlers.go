package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
)

type ListCertsResponse struct {
	Certificates []string `json:"certificates"`
}

type UploadSignedCertRequest struct {
	Certificate string `json:"certificate"`
}

func HandleListCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Logger.Debug("Rejected request due to invalid HTTP method",
			"received_method", r.Method,
			"expected_method", http.MethodGet,
			"endpoint", r.URL.Path,
		)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	certs := identity.ListOCSPCerts()

	response := ListCertsResponse{
		Certificates: certs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		Logger.Error("Failed to encode response",
			"error", err,
		)

		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

}

func HandleUploadSignedCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Logger.Debug("Rejected request due to invalid HTTP method",
			"received_method", r.Method,
			"expected_method", http.MethodGet,
			"endpoint", r.URL.Path,
		)

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Validation
	var req UploadSignedCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Logger.Warn("Invalid JSON body",
			"error", err,
			"status", http.StatusBadRequest,
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
		)

		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	err := identity.AddOCSPCert(req.Certificate)
	if err != nil {
		Logger.Error("Failed to add OCSP cert",
			"error", err,
		)
		http.Error(w, "Failed to Upload Certificate", http.StatusInternalServerError)
		return
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
	if r.Method != http.MethodPost {
		Logger.Debug("Rejected request due to invalid HTTP method",
			"received_method", r.Method,
			"expected_method", http.MethodGet,
			"endpoint", r.URL.Path,
		)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Validation
	var req createNewCsrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Logger.Warn("Invalid JSON body",
			"error", err,
			"status", http.StatusBadRequest,
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
		)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
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

	response := createNewCsrResponse{
		CSR: string(csrPEM),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		Logger.Error("Failed to encode response",
			"error", err,
		)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
