package list

import (
	"errors"
	"fmt"
	"github.com/intunderflow/metal/mtls"
	"github.com/intunderflow/metal/net"
	"github.com/intunderflow/metal/rollout"
	"github.com/spf13/cobra"
)

var broker string
var detailed bool
var detailedFirstRollout bool
var mtlsCertFilePath string
var mtlsKeyFilePath string

func Cmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "list",
		Short: "List rollouts on a federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if broker == "" {
				return errors.New("broker is required")
			}

			client, err := mtls.GetClient(mtlsCertFilePath, mtlsKeyFilePath)
			if err != nil {
				return err
			}

			config, err := net.NewBroker(broker, client).GetConfig(cmd.Context())
			if err != nil {
				return err
			}

			rolloutService := rollout.NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			rollouts, err := rolloutService.GetRollouts(config)
			if err != nil {
				return err
			}
			fmt.Printf("-%d rollouts\n", len(rollouts))
			for i, currentRollout := range rollouts {
				fmt.Printf("#%d: node %s - %s\n", i+1, currentRollout.NodeID(), currentRollout.BasicDisplayTextForHumans())
				if detailed || (i == 0 && detailedFirstRollout) {
					fmt.Printf("%s\n", currentRollout.DetailedDisplayTextForHumans())
				}
			}
			return nil
		},
	}
	list.PersistentFlags().StringVar(&broker, "broker", "", "Broker server URL")
	list.PersistentFlags().BoolVar(&detailed, "detailed", false, "Show detailed rollout information")
	list.PersistentFlags().BoolVar(&detailedFirstRollout, "detailed-first-rollout", false, "Show detailed rollout information for the first rollout")
	list.PersistentFlags().StringVar(&mtlsCertFilePath, "mtls-cert-file-path", "", "Mutual TLS Certificate File Path")
	list.PersistentFlags().StringVar(&mtlsKeyFilePath, "mtls-key-file-path", "", "Mutual TLS Key File Path")
	return list
}
