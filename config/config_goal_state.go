package config

import (
	"encoding/json"
	"time"
)

type NodeGoalState struct {
	// ID of the node, used to insert the node correctly in the config
	ID string `json:"id"`

	// Timestamp when the configuration for this node was issued
	CreatedAt time.Time `json:"created_at"`

	// If this boolean is true the other nodes will attempt to connect to this node as part of their wireguard mesh
	WireguardMeshMember bool `json:"wireguard_mesh_member"`

	// If this boolean is true the other nodes will make this node part of their etcd quorums
	EtcdMember bool `json:"etcd_member"`

	// If this boolean is true then the node will be part of the Kubernetes control plane
	KubernetesControlPlane bool `json:"kubernetes_control_plane"`

	// If this boolean is true then the node will be a Kubernetes worker
	KubernetesWorker bool `json:"kubernetes_worker"`

	// The URL of the Kubernetes API server binary to use (maps to kube-apiserver)
	KubernetesAPIServerBinary string `json:"kubernetes_api_server_binary"`

	// The hash of the content expected at the URL of the Kubernetes API server binary (if empty no hash check is done)
	KubernetesAPIServerBinaryHash string `json:"kubernetes_api_server_binary_hash"`
}

func (n *NodeGoalState) ContentsForSignature() ([]byte, error) {
	marshalled, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	return append([]byte("NodeGoalState."), marshalled...), nil
}
