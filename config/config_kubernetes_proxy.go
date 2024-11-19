package config

type KubernetesProxySpec struct {
	KubeconfigPath string `json:"kubeconfig_path"`
	ClusterCIDR    string `json:"cluster_cidr"`
}
