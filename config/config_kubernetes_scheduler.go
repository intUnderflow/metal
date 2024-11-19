package config

type KubernetesSchedulerSpec struct {
	ServerAddress    string `json:"server_address"`
	AdvertiseAddress string `json:"advertise_address"`
	SecurePort       int    `json:"secure_port"`
}
