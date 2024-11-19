package config

import (
	"fmt"
	"github.com/intunderflow/metal/crypto"
	"time"
)

// AddNode is used by admin certificates to add a node
func (c *Config) AddNode(id string, signer crypto.Signer) error {
	node, err := newNode(id, signer)
	if err != nil {
		return err
	}
	c.Nodes[id] = node
	return nil
}

// UpdateNodeGoalState is used by admin certificates to update a goal state for a node
func (c *Config) UpdateNodeGoalState(id string, goalState *NodeGoalState, signer crypto.Signer) error {
	node, ok := c.Nodes[id]
	if !ok {
		return fmt.Errorf("node %s does not exist", id)
	}

	signature, err := signer.Sign(goalState)
	if err != nil {
		return err
	}

	node.GoalState = goalState
	node.GoalStateSignature = signature
	return nil
}

func newNode(id string, signer crypto.Signer) (*Node, error) {
	goalState := &NodeGoalState{
		ID:                  id,
		CreatedAt:           time.Now(),
		WireguardMeshMember: false,
		EtcdMember:          false,
	}
	signature, err := signer.Sign(goalState)
	if err != nil {
		return nil, err
	}
	return &Node{
		GoalState:          goalState,
		GoalStateSignature: signature,
	}, nil
}
