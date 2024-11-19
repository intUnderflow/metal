package create_kubeconfig

import (
	_ "embed"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

//go:embed kubeconfig.yaml
var _kubeconfig string

var caPath string
var serverAddress string
var certificatePath string
var privateKeyPath string
var outputPath string

func Cmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "create-kubeconfig",
		Short: "Creates a kubeconfig from a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if caPath == "" {
				return errors.New("ca-path is required")
			}
			if serverAddress == "" {
				return errors.New("server-address is required")
			}
			if certificatePath == "" {
				return errors.New("certificate-path is required")
			}
			if privateKeyPath == "" {
				return errors.New("private-key-path is required")
			}
			if outputPath == "" {
				return errors.New("output-path is required")
			}

			configFile := strings.ReplaceAll(_kubeconfig, "$CA_DATA_PATH", fmt.Sprintf("\"%s\"", caPath))
			configFile = strings.ReplaceAll(configFile, "$SERVER_ADDRESS", fmt.Sprintf("\"%s\"", serverAddress))
			configFile = strings.ReplaceAll(configFile, "$CLIENT_CERTIFICATE_PATH", fmt.Sprintf("\"%s\"", certificatePath))
			configFile = strings.ReplaceAll(configFile, "$CLIENT_KEY_PATH", fmt.Sprintf("\"%s\"", privateKeyPath))

			err := os.WriteFile(outputPath, []byte(configFile), 0600)
			if err != nil {
				return err
			}

			return nil
		},
	}
	list.PersistentFlags().StringVar(&caPath, "ca-path", "", "File path of root CA file")
	list.PersistentFlags().StringVar(&serverAddress, "server-address", "", "Address of server")
	list.PersistentFlags().StringVar(&certificatePath, "certificate-path", "", "File path of certificate")
	list.PersistentFlags().StringVar(&privateKeyPath, "private-key-path", "", "File path of private key")
	list.PersistentFlags().StringVar(&outputPath, "output-path", "", "File path to output to")
	return list
}
