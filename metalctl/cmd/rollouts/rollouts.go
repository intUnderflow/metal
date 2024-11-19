package rollouts

import (
	"github.com/intunderflow/metal/metalctl/cmd/rollouts/list"
	"github.com/spf13/cobra"
)

func Cmd() *cobra.Command {
	rollouts := &cobra.Command{
		Use:   "rollouts",
		Short: "Read rollout status",
	}
	rollouts.AddCommand(list.Cmd())
	return rollouts
}
