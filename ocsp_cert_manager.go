package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func isValidOCSPSigning(cert *x509.Certificate) error {
	// Check key usage
	hasDigitalSignature := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	hasOCSPSigning := false

	// Check extended key usage
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}

	// Return true if both conditions are met
	if hasDigitalSignature && hasOCSPSigning {
		return nil
	}
	return errors.New("certificate does not qualify as ocsp certificate")
}

type OCSPResponder struct {
	OcspCert   *x509.Certificate
	IssuerCert *x509.Certificate
}

func (o *OCSPResponder) ToPEM() string {
	// Encode the OCSP certificate to PEM
	ocspPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: o.OcspCert.Raw,
	})

	// Encode the Issuer certificate to PEM
	issuerPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: o.IssuerCert.Raw,
	})

	// Concatenate the two PEM blocks
	return string(ocspPEM) + string(issuerPEM)
}
func (o *OCSPResponder) ComputeIssuerKeyHash() (string, error) {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(o.IssuerCert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return "", fmt.Errorf("failed to unmarshal subjectPublicKeyInfo: %w", err)
	}
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

func LoadOCSPResponderFromFile(filename string) (*OCSPResponder, error) {
	// Read the entire file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file %q: %w", filename, err)
	}

	// Decode the first PEM block (OCSP certificate)
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode the first PEM block")
	}
	ocspCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP certificate: %w", err)
	}

	// Decode the second PEM block (Issuer certificate)
	block, _ = pem.Decode(rest)
	if block == nil {
		return nil, fmt.Errorf("failed to decode the second PEM block")
	}
	issuerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	// Return a new OCSPResponder instance with the parsed certificates.
	return &OCSPResponder{
		OcspCert:   ocspCert,
		IssuerCert: issuerCert,
	}, nil
}

type OCSPCertManager struct {
	certsFolderPath string
	responders      map[string]OCSPResponder //IssuerKeyHash -> Responder
}

func (o *OCSPCertManager) Init() error {
	err := o.LoadCertsFromDisk()
	if err != nil {
		return err
	}
	return nil
}

func (o *OCSPCertManager) LoadCertsFromDisk() error {
	files, err := os.ReadDir(o.certsFolderPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) == ".pem" {
			filePath := filepath.Join(o.certsFolderPath, file.Name())

			r, err := LoadOCSPResponderFromFile(filePath)
			if err != nil {
				return err
			}
			issuerKeyHash, err := r.ComputeIssuerKeyHash()
			if err != nil {
				return err
			}
			//make sure the list stays unique
			if _, exists := o.responders[issuerKeyHash]; exists {
				return fmt.Errorf("a responder for this issuer already exists")
			}

			err = identity.PrivateKeyMatchesCert(r.OcspCert)
			if err != nil {
				return err
			}
			err = isValidOCSPSigning(r.OcspCert)
			if err != nil {
				return err
			}
			o.responders[issuerKeyHash] = *r
		}
	}
	return nil
}

func (o *OCSPCertManager) ListOCSPCerts() []OCSPResponder {
	r := []OCSPResponder{}
	for _, responder := range o.responders {
		r = append(r, responder)
	}
	return r
}

func (o *OCSPCertManager) RemoveResponder(issuerKeyHash string) error {
	if _, exists := o.responders[issuerKeyHash]; !exists {
		return fmt.Errorf("key %q does not exist", issuerKeyHash)
	}
	delete(o.responders, issuerKeyHash)
	return nil
}

func (o *OCSPCertManager) AddResponder(r OCSPResponder) error {
	issuerHashString, err := r.ComputeIssuerKeyHash()
	if err != nil {
		return err
	}
	err = identity.PrivateKeyMatchesCert(r.OcspCert)
	if err != nil {
		return err
	}
	err = isValidOCSPSigning(r.OcspCert)
	if err != nil {
		return err
	}
	if _, exists := o.responders[issuerHashString]; exists {
		return fmt.Errorf("a responder for this issuer already exists")
	}

	o.responders[issuerHashString] = r

	filename := fmt.Sprintf("%s.pem", issuerHashString)
	filePath := filepath.Join(o.certsFolderPath, filename)

	err = os.MkdirAll(o.certsFolderPath, 0755)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, []byte(r.ToPEM()), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (db *OCSPCertManager) IssuerExists(issuerKeyHash string) bool {
	_, exists := db.responders[issuerKeyHash]
	return exists
}
