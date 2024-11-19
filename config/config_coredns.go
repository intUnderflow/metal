package config

type CoreDNSSpec struct {
	Endpoint string `json:"endpoint"`
	Port     int    `json:"port"`
}
