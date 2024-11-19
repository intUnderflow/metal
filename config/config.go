package config

import (
	"encoding/json"
	"github.com/intunderflow/metal/crypto"
)

type Config struct {
	// Map of the nodes, the key is the node ID
	Nodes map[string]*Node `json:"nodes"`
}

type Node struct {
	// GoalState of the node
	// Set manually by the Admin (typically an offline device)
	GoalState *NodeGoalState `json:"goal_state"`
	// The subject name of the certificate MUST begin with "admin-" and it MUST be signed by the root CA
	GoalStateSignature *crypto.Signature `json:"goal_state_signature"`

	// ActualState of the node
	// Set by the node using its X509CertificatePEM
	ActualState *NodeActualState `json:"actual_state"`
	// The subject name of the node MUST match the ID parameter AND it MUST be signed by the root CA
	ActualStateSignature *crypto.Signature `json:"actual_state_signature"`
}

func NewConfig() *Config {
	return &Config{
		Nodes: map[string]*Node{},
	}
}

func FromBytes(bytes []byte) (*Config, error) {
	var config Config
	err := json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
