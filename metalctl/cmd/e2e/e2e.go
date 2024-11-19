package e2e

import (
	"github.com/intunderflow/metal/metalctl/cmd/e2e/verify-node-actualstate-exists"
	"github.com/spf13/cobra"
)

func Cmd() *cobra.Command {
	e2e := &cobra.Command{
		Use:   "e2e",
		Short: "Verify system working as part of e2e tests",
	}
	e2e.AddCommand(verifynodeactualstateexists.Cmd())
	return e2e
}
