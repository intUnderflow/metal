package config

import (
	"errors"
	"fmt"
	"github.com/intunderflow/metal/crypto"
)

// UpdateNodeActualState is used by nodes to update their own actual state
func (c *Config) UpdateNodeActualState(id string, actualState *NodeActualState, signer crypto.Signer) error {
	node, ok := c.Nodes[id]
	if !ok {
		return fmt.Errorf("node %s does not exist", id)
	}

	signature, err := signer.Sign(actualState)
	if err != nil {
		return err
	}

	node.ActualState = actualState
	node.ActualStateSignature = signature
	return nil
}

// Verify verifies that the Node is well-formed and signed appropriately
func (n *Node) Verify(id string, verifier crypto.Verifier) error {
	if n.GoalState == nil {
		return errors.New("all nodes must have GoalState")
	}

	if n.GoalState.ID != id {
		return fmt.Errorf("all nodes must match their ID to the one in their GoalState, claimed ID: %s, GoalState ID: %s", id, n.GoalState.ID)
	}

	err := verifier.Verify(n.GoalStateSignature, n.GoalState, ".admin.metal.local")
	if err != nil {
		return err
	}

	if n.ActualState != nil {
		err = verifier.Verify(n.ActualStateSignature, n.ActualState, n.GoalState.ID+".node.metal.local")
		if err != nil {
			return err
		}
	}

	return nil
}
