package node

import (
	"github.com/intunderflow/metal/metalctl/cmd/node/create"
	"github.com/intunderflow/metal/metalctl/cmd/node/list"
	"github.com/spf13/cobra"
)

func Cmd() *cobra.Command {
	node := &cobra.Command{
		Use:   "node",
		Short: "Read and write node information",
	}
	node.AddCommand(list.Cmd())
	node.AddCommand(create.Cmd())
	return node
}
