package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

type Signature struct {
	X509CertificatePEM string `json:"x509_certificate_pem"`
	Signature          string `json:"signature"`
}

type Signable interface {
	ContentsForSignature() ([]byte, error)
}

type Signer interface {
	Sign(Signable) (*Signature, error)
}

type certSigner struct {
	key     *rsa.PrivateKey
	cert    tls.Certificate
	certPEM string
}

func (c *certSigner) Sign(sign Signable) (*Signature, error) {
	content, err := sign.ContentsForSignature()
	if err != nil {
		return nil, err
	}

	hashedContents := sha512.Sum512(content)
	signature, err := rsa.SignPKCS1v15(nil, c.key, crypto.SHA512, hashedContents[:])
	if err != nil {
		return nil, err
	}

	return &Signature{
		X509CertificatePEM: c.certPEM,
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func SignerFromFile(certFilePath string, keyFilePath string) (Signer, error) {
	cert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("cannot cast private key to rsa.PrivateKey")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	return &certSigner{
		key:     rsaKey,
		cert:    cert,
		certPEM: string(certPEM),
	}, nil
}
