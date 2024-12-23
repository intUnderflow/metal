package config

import (
	"encoding/json"
	"time"
)

type NodeActualState struct {
	// ID of the node, used to insert the node correctly in the config
	ID string `json:"id"`

	// Timestamp when the state information for this node was issued
	CreatedAt time.Time `json:"created_at"`

	// Endpoint of the node, this can be a string or IP with a port, for example metal-1.lucy.sh:1234 or 12.13.14.15:1234
	Endpoint string `json:"endpoint"`

	// ReconciliationStatus reports any errors from the node in their reconciliation work, if no error this is a blank string
	ReconciliationStatus string `json:"reconciliation_status"`

	// Wireguard Public Key of the node
	WireguardPublicKey string `json:"wireguard_public_key"`

	// The wireguard configuration on the node
	WireguardSpec *WireguardSpec `json:"wireguard_spec"`

	// Indicates if Wireguard is healthy, "HEALTHY" indicates this, any other string is an error
	WireguardStatus string `json:"wireguard_status"`

	// The DNS configuration of the node
	DNSSpec *DNSSpec `json:"dns_spec"`

	// The etcd configuration on the node
	EtcdSpec *EtcdSpec `json:"etcd_spec"`

	// Indicates if etcd is healthy, "HEALTHY" indicates this, any other string is an error
	EtcdStatus string `json:"etcd_status"`

	// The kubernetes API server configuration on the node
	KubernetesAPIServerSpec *KubernetesAPIServerSpec `json:"kubernetes_api_server_spec"`

	// Indicates if the Kubernetes API server is healthy, "HEALTHY" indicates this, any other string is an error
	KubernetesAPIServerStatus string `json:"kubernetes_api_server_status"`

	// KubernetesAPIServerRootCA is the root CA generated by the node for the Kubernetes API server
	KubernetesAPIServerRootCA string `json:"kubernetes_api_server_root_ca"`

	// KubernetesAPIServerServiceAccountPublicKey is the public key used by the node API server to sign service account tokens
	KubernetesAPIServerServiceAccountPublicKey string `json:"kubernetes_api_server_service_account_public_key"`

	// KubernetesControllerManagerSpec is the spec for the kube-controller-manager on the node
	KubernetesControllerManagerSpec *KubernetesControllerManagerSpec `json:"kubernetes_controller_manager_spec"`

	// Indicates if the Kubernetes controller manager is healthy, "HEALTHY" indicates this, any other string is an error
	KubernetesControllerManagerStatus string `json:"kubernetes_controller_manager_status"`

	// KubernetesSchedulerSpec is the spec for the kube-scheduler on the node
	KubernetesSchedulerSpec *KubernetesSchedulerSpec `json:"kubernetes_scheduler_spec"`

	// Indicates if the Kubernetes scheduler is healthy, "HEALTHY" indicates this, any other string is an error
	KubernetesSchedulerStatus string `json:"kubernetes_scheduler_status"`

	// KubernetesKubeletSpec is the spec for the kubernetes kubelet on the node
	KubernetesKubeletSpec *KubernetesKubeletSpec `json:"kubernetes_kubelet_spec"`

	// KubernetesKubeletStatus is the status of the Kubernetes kubelet service
	KubernetesKubeletStatus *KubernetesKubeletStatus `json:"kubernetes_kubelet_status"`

	// CoreDNSSpec is the spec for CoreDNS
	CoreDNSSpec *CoreDNSSpec `json:"core_dns_spec"`

	// Indicates if CoreDNS is healthy, "HEALTHY" indicates this, any other string is an error
	CoreDNSStatus string `json:"core_dns_status"`

	// KubernetesProxySpec is the spec for the kube-proxy on the node
	KubernetesProxySpec *KubernetesProxySpec `json:"kubernetes_proxy_spec"`

	// KubernetesProxyStatus is the status of the kube-proxy service
	KubernetesProxyStatus string `json:"kubernetes_proxy_status"`

	// DownloadedBinaries is a map of binary names onto SHA256 hashes present on the node, it is used to determine
	// if a binary needs to be updated
	DownloadedBinaries map[string]string `json:"downloaded_binaries"`

	// ExtraData is the ExtraData from the goal state that has been written to disk
	ExtraData map[string]string `json:"extra_data"`

	// CustomRolloutState contains state from custom rollouts
	CustomRolloutState map[string]string `json:"custom_rollout_state"`
}

func (n *NodeActualState) ContentsForSignature() ([]byte, error) {
	marshalled, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	return append([]byte("NodeActualState."), marshalled...), nil
}
