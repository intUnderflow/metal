package config

type KubernetesProxySpec struct {
	Name          string `json:"name"`
	ServerAddress string `json:"server_address"`
	ClusterCIDR   string `json:"cluster_cidr"`
}
