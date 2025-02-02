package verifynodeactualstateexists

import (
	"context"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/mtls"
	"github.com/intunderflow/metal/net"
	"github.com/spf13/cobra"
	"time"
)

var broker string
var attempts int
var delay int
var mtlsCertFilePath string
var mtlsKeyFilePath string

func Cmd() *cobra.Command {
	verifyNodeActualstateExists := &cobra.Command{
		Use:   "verify-node-actualstate-exists",
		Short: "Verify there is a present ActualState for a given node on a broker",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeID := args[0]

			if broker == "" {
				return errors.New("broker is required")
			}

			client, err := mtls.GetClient(mtlsCertFilePath, mtlsKeyFilePath)
			if err != nil {
				return err
			}

			cmdBroker := net.NewBroker(broker, client)

			attempt := 1
			for {
				err = runOnce(cmd.Context(), cmdBroker, nodeID)
				if err != nil {
					fmt.Printf("error on attempt %d: %v\n", attempt, err)
					attempt = attempt + 1
					if attempt > attempts {
						return errors.New("maximum attempts reached")
					}
					time.Sleep(time.Second * time.Duration(delay))
				} else {
					fmt.Printf("successfully verified actual state for node %s\n", nodeID)
					return nil
				}
			}
		},
	}
	verifyNodeActualstateExists.PersistentFlags().StringVar(&broker, "broker", "", "Broker server URL")
	verifyNodeActualstateExists.PersistentFlags().IntVar(&attempts, "attempts", 1, "Maximum attempts")
	verifyNodeActualstateExists.PersistentFlags().IntVar(&delay, "delay", 5, "Delay between attempts")
	verifyNodeActualstateExists.PersistentFlags().StringVar(&mtlsCertFilePath, "mtls-cert-file-path", "~/.metal/admin.pem", "Mutual TLS Certificate File Path")
	verifyNodeActualstateExists.PersistentFlags().StringVar(&mtlsKeyFilePath, "mtls-key-file-path", "~/.metal/admin.key", "Mutual TLS Key File Path")
	return verifyNodeActualstateExists
}

func runOnce(ctx context.Context, broker net.Broker, nodeIDToFind string) error {
	nodes, err := broker.ListNodes(ctx)
	if err != nil {
		return err
	}

	for nodeID, nodeConfig := range nodes {
		if nodeID == nodeIDToFind {
			if nodeConfig.ActualState != nil {
				fmt.Printf("node %s has active state\n", nodeID)
				return nil
			} else {
				return fmt.Errorf("node %s has no active state", nodeID)
			}
		}
	}

	return fmt.Errorf("node %s does not exist", nodeIDToFind)
}
