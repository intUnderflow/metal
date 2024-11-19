package create_certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
	"github.com/spf13/cobra"
	"os"
)

var caPath string
var certificateType string
var commonName string
var outputPath string

func Cmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "create-certificate",
		Short: "Creates a certificate from a local CA file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if caPath == "" {
				return errors.New("ca-path is required")
			}
			if certificateType == "" {
				return errors.New("certificate-type is required")
			}
			if commonName == "" {
				return errors.New("common-name is required")
			}
			if outputPath == "" {
				return errors.New("output-path is required")
			}
			switch certificateType {
			case "kube-superadmin":
				{
					return issueKubeSuperAdminCertificate(caPath, commonName, outputPath)
				}
			}
			return fmt.Errorf("certificate-type %s not supported", certificateType)
		},
	}
	list.PersistentFlags().StringVar(&caPath, "ca-path", "", "File path of root CA file")
	list.PersistentFlags().StringVar(&certificateType, "certificate-type", "", "Type of certificate to create")
	list.PersistentFlags().StringVar(&commonName, "common-name", "", "Common name to issue certificate to")
	list.PersistentFlags().StringVar(&outputPath, "output-path", "", "File path to output to, .pem will contain certificate, .key will contain private key")
	return list
}

func issueKubeSuperAdminCertificate(caPath string, commonName string, outputPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	marshalledKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	pkiService, err := pki.NewPKIFromExisting(caPath)
	if err != nil {
		return err
	}

	cert, err := pkiService.IssueSuperAdminCertificate(commonName, &key.PublicKey)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshalledKey,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	err = os.WriteFile(outputPath+".pem", certPEM, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(outputPath+".key", keyPEM, 0600)
	if err != nil {
		return err
	}

	return nil
}
