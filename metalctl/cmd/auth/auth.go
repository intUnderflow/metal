package auth

import (
	create_certificate "github.com/intunderflow/metal/metalctl/cmd/auth/create-certificate"
	create_kubeconfig "github.com/intunderflow/metal/metalctl/cmd/auth/create-kubeconfig"
	"github.com/spf13/cobra"
)

func Cmd() *cobra.Command {
	auth := &cobra.Command{
		Use:   "auth",
		Short: "Authentication utility commands",
	}
	auth.AddCommand(create_certificate.Cmd())
	auth.AddCommand(create_kubeconfig.Cmd())
	return auth
}
