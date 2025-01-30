package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	FolderPath string
	privateKey *ecdsa.PrivateKey
	ocspCerts  []string //pem encoded string
}

func (i *Identity) AddOCSPCert(cert string) {
	for _, existingCert := range i.ocspCerts {
		if existingCert == cert {
			return
		}

	}

	i.ocspCerts = append(i.ocspCerts, cert)
}

func (i *Identity) ListOCSPCerts() []string {
	return i.ocspCerts
}

func (i *Identity) GetPublicKey() (*ecdsa.PublicKey, error) {
	if i.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}

	return &i.privateKey.PublicKey, nil
}

func (i *Identity) GetOrCreatePrivateKey() error {
	const privateKeyFilename = "priv.pem"

	privateKeyFullpath := filepath.Join(i.FolderPath, privateKeyFilename)

	_, err := os.Stat(privateKeyFullpath)
	if err == nil {
		data, err := os.ReadFile(privateKeyFullpath)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block from %s", privateKeyFullpath)
		}

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		i.privateKey = key
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	fmt.Println("Key not found, generating a new ECDSA key...")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.Create(privateKeyFullpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	i.privateKey = key

	return nil
}

func (i *Identity) CreateCsr(csrTemplate *x509.CertificateRequest) ([]byte, error) {
	if i.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, i.privateKey)
	if err != nil {
		return []byte{}, err
	}
	return csrBytes, nil
}
