package cmd

import (
	"github.com/intunderflow/metal/metalctl/cmd/auth"
	"github.com/intunderflow/metal/metalctl/cmd/e2e"
	"github.com/intunderflow/metal/metalctl/cmd/node"
	"github.com/intunderflow/metal/metalctl/cmd/rollouts"
	"github.com/spf13/cobra"
)

func Cmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "metalctl",
		Short: "Control a metal federation",
	}
	root.AddCommand(auth.Cmd())
	root.AddCommand(node.Cmd())
	root.AddCommand(rollouts.Cmd())
	root.AddCommand(e2e.Cmd())
	return root
}
