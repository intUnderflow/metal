package config

type KubernetesAPIServerSpec struct {
	EtcdServers                 []string          `json:"etcd_servers"`
	AdvertiseAddress            string            `json:"advertise_address"`
	SecurePort                  int               `json:"secure_port"`
	FeatureGates                map[string]bool   `json:"feature_gates"`
	CertificatePEMs             map[string]string `json:"certificate_pems"`
	ServiceAccountPublicKeyPEMs map[string]string `json:"service_account_public_key_pems"`
}
