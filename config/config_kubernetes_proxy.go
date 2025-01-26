package config

type KubernetesProxySpec struct {
	ServerAddress string `json:"server_address"`
	ClusterCIDR   string `json:"cluster_cidr"`
}
