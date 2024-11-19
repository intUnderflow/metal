package config

type WireguardSpec struct {
	Peers    []WireguardPeer `json:"peers"`
	SelfPeer WireguardPeer   `json:"self_peer"`
}

type WireguardPeer struct {
	PeerID      string `json:"peer_id"`
	Endpoint    string `json:"endpoint"`
	Port        int    `json:"port"`
	PublicKey   string `json:"public_key"`
	BindLocalIP string `json:"bind_local_ip"`
}
