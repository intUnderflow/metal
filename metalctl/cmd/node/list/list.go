package list

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/mtls"
	"github.com/intunderflow/metal/net"
	"github.com/spf13/cobra"
)

var broker string
var mtlsCertFilePath string
var mtlsKeyFilePath string
var hideGoalState bool
var hideActualState bool
var hideReconciliationStatus bool

func Cmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "list",
		Short: "List nodes on a federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if broker == "" {
				return errors.New("broker is required")
			}

			client, err := mtls.GetClient(mtlsCertFilePath, mtlsKeyFilePath)
			if err != nil {
				return err
			}

			nodes, err := net.NewBroker(broker, client).ListNodes(cmd.Context())
			if err != nil {
				return err
			}

			fmt.Printf("There are %d nodes\n", len(nodes))
			for id, node := range nodes {
				fmt.Printf("Node %s\n", id)
				if !hideGoalState {
					if node.GoalState != nil {
						marshalledGoalState, err := json.MarshalIndent(node.GoalState, "", "    ")
						if err != nil {
							fmt.Printf("Goal state: ERR %v\n", err)
						} else {
							fmt.Printf("Goal state: %s\n", string(marshalledGoalState))
						}
					} else {
						fmt.Printf("Goal state: EMPTY\n")
					}
				}
				if !hideActualState {
					if node.ActualState != nil {
						marshalledActualState, err := json.MarshalIndent(node.ActualState, "", "    ")
						if err != nil {
							fmt.Printf("Actual state: ERR %v\n", err)
						} else {
							fmt.Printf("Actual state: %s\n", marshalledActualState)
						}
					} else {
						fmt.Printf("Actual state: EMPTY\n")
					}
				}
				if !hideReconciliationStatus {
					if node.ActualState != nil {
						fmt.Printf("Reconciliation status: %s\n", toReconciliationStatus(node.ActualState.ReconciliationStatus))
					} else {
						fmt.Printf("Reconciliation status: UNKNOWN\n")
					}
				}
			}
			return nil
		},
	}
	list.PersistentFlags().StringVar(&broker, "broker", "", "Broker server URL")
	list.PersistentFlags().StringVar(&mtlsCertFilePath, "mtls-cert-file-path", "~/.metal/admin.pem", "Mutual TLS Certificate File Path")
	list.PersistentFlags().StringVar(&mtlsKeyFilePath, "mtls-key-file-path", "~/.metal/admin.key", "Mutual TLS Key File Path")
	list.PersistentFlags().BoolVar(&hideGoalState, "hide-goal-state", false, "Hide Goal State")
	list.PersistentFlags().BoolVar(&hideActualState, "hide-actual-state", false, "Hide Actual State")
	list.PersistentFlags().BoolVar(&hideReconciliationStatus, "hide-reconciliation-status", false, "Hide Reconciliation Status")
	return list
}

func toReconciliationStatus(status string) string {
	if status == "" {
		return "OK"
	} else {
		return "ERROR: " + status
	}
}
