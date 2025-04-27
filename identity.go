package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ocsp"
)

type Identity struct {
	PrivateKeyPath string
	privateKey     *ecdsa.PrivateKey
}

func (i *Identity) CreateResponse(issuerCert *x509.Certificate, responderCert *x509.Certificate, template ocsp.Response) ([]byte, error) {
	return ocsp.CreateResponse(issuerCert, responderCert, template, i.privateKey)
}

func (i *Identity) PrivateKeyMatchesCert(cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("certificate public key is not ECDSA")
	}
	if pub.Curve != i.privateKey.PublicKey.Curve ||
		pub.X.Cmp(i.privateKey.PublicKey.X) != 0 ||
		pub.Y.Cmp(i.privateKey.PublicKey.Y) != 0 {
		return errors.New("private does not match certificate")
	}
	return nil
}

func (i *Identity) Init() error {
	err := i.LoadOrCreatePrivateKey()
	if err != nil {
		return err
	}
	return nil
}

func (i *Identity) GetPublicKey() (*ecdsa.PublicKey, error) {
	if i.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}

	return &i.privateKey.PublicKey, nil
}

func (i *Identity) LoadOrCreatePrivateKey() error {

	privateKeyFullpath := i.PrivateKeyPath
	if data, err := os.ReadFile(privateKeyFullpath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block from %s", privateKeyFullpath)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		i.privateKey = key
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	Logger.Info("Key not found, generating a new ECDSA key...")

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

	if err := os.MkdirAll(filepath.Dir(privateKeyFullpath), 0o755); err != nil { // falls Unterverz. fehlt
		return err
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
