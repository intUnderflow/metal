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

	// Controls the provisioning method, valid values are metal or kubeadm.
	KubernetesProvisionMethod string `json:"kubernetes_provision_method"`

	// The URL of the etcd binary to use (maps to etcd)
	EtcdBinary string `json:"etcd_binary"`

	// The hash of the content expected at the URL of the etcd binary (if empty no hash check is done)
	EtcdBinaryHash string `json:"etcd_binary_hash"`

	// The URL of the Kubernetes API server binary to use (maps to kube-apiserver)
	KubernetesAPIServerBinary string `json:"kubernetes_api_server_binary"`

	// The hash of the content expected at the URL of the Kubernetes API server binary (if empty no hash check is done)
	KubernetesAPIServerBinaryHash string `json:"kubernetes_api_server_binary_hash"`

	// The URL of the Kubernetes controller manager binary to use (maps to kube-controller-manager)
	KubernetesControllerManagerBinary string `json:"kubernetes_controller_manager_binary"`

	// The hash of the content expected at the URL of the Kubernetes controller manager binary (if empty no hash check is done)
	KubernetesControllerManagerBinaryHash string `json:"kubernetes_controller_manager_binary_hash"`

	// The URL of the Kubernetes scheduler binary to use (maps to kube-scheduler)
	KubernetesSchedulerBinary string `json:"kubernetes_scheduler_binary"`

	// The hash of the content expected at the URL of the Kubernetes scheduler binary (if empty no hash check is done)
	KubernetesSchedulerBinaryHash string `json:"kubernetes_scheduler_binary_hash"`

	// The URL of the Kubernetes kubelet binary to use (maps to kubelet)
	KubernetesKubeletBinary string `json:"kubernetes_kubelet_binary"`

	// The hash of the content expected at the URL of the Kubernetes kubelet binary (if empty no hash check is done)
	KubernetesKubeletBinaryHash string `json:"kubernetes_kubelet_binary_hash"`

	// The url of the Kubernetes proxy binary to use (maps to kube-proxy)
	KubernetesProxyBinary string `json:"kubernetes_kube_proxy_binary"`

	// The hash of the content expected at the URL of the Kubernetes proxy binary (if empty no hash check is done)
	KubernetesProxyBinaryHash string `json:"kubernetes_kube_proxy_binary_hash"`

	// The url of the CoreDNS binary to use (maps to coredns)
	CoreDNSBinary string `json:"coredns_binary"`

	// The hash of the content expected at the URL of the CoreDNS binary (if empty no hash check is done)
	CoreDNSBinaryHash string `json:"coredns_binary_hash"`

	// The url of the Kubeadm binary to use (maps to kubeadm)
	KubeadmBinary string `json:"kubeadm_binary"`

	// The hash of the content expected at the URL of the Kubeadm binary (if empty no hash check is done)
	KubeadmBinaryHash string `json:"kubeadm_binary_hash"`

	// CustomRolloutSpec is the custom rollouts configured for the node
	CustomRolloutSpec map[string]CustomRolloutSpec `json:"custom_rollout_spec"`
}

func (n *NodeGoalState) ContentsForSignature() ([]byte, error) {
	marshalled, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	return append([]byte("NodeGoalState."), marshalled...), nil
}
