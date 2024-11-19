package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

func GetClient(certFilePath string, keyFilePath string) (*http.Client, error) {
	systemCA, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	clientCertAndKey, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      systemCA,
				Certificates: []tls.Certificate{clientCertAndKey},
			},
		},
	}
	return client, nil
}
