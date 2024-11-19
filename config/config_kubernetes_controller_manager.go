package config

type KubernetesControllerManagerSpec struct {
	ServerAddress    string `json:"server_address"`
	AdvertiseAddress string `json:"advertise_address"`
	SecurePort       int    `json:"secure_port"`
	ClusterCIDR      string `json:"cluster_cidr"`
}
