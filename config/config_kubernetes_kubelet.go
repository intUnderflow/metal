package config

type KubernetesKubeletStatus struct {
	CertificateRequest *KubernetesKubeletCertificateRequest `json:"certificate_request"`
	CertificateFulfill map[string]string                    `json:"certificate_fulfill"`
	KubeconfigPath     string                               `json:"kubeconfig_path"`
	Status             string                               `json:"status"`
}

type KubernetesKubeletCertificateRequest struct {
	PublicKey string `json:"public_key"`
}

type KubernetesKubeletSpec struct {
	APIServerAddress string            `json:"server_address"`
	CertificatePEMs  map[string]string `json:"certificate_pems"`
	KubeletAddress   string            `json:"kubelet_address"`
	SecurePort       int               `json:"secure_port"`
	Name             string            `json:"name"`
	ClusterDNS       []string          `json:"cluster_dns"`
}
