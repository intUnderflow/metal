package config

type EtcdSpec struct {
	Name  string              `json:"name"`
	Peers map[string]EtcdPeer `json:"peers"`
}

type EtcdPeer struct {
	PeerEndpoint   string `json:"peer_endpoint"`
	ClientEndpoint string `json:"client_endpoint"`
}
