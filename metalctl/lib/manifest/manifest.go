package manifest

import (
	"encoding/json"
	"os"
)

type Manifest struct {
	KubeAPIServer         Entry `json:"kube-apiserver"`
	KubeControllerManager Entry `json:"kube-controller-manager"`
	KubeScheduler         Entry `json:"kube-scheduler"`
	Kubelet               Entry `json:"kubelet"`
	KubeProxy             Entry `json:"kube-proxy"`
}

type Entry struct {
	URL  string `json:"url"`
	Hash string `json:"hash,omitempty"`
}

func FromFile(filename string) (*Manifest, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	manifest := Manifest{}
	err = json.Unmarshal(bytes, &manifest)
	if err != nil {
		return nil, err
	}

	return &manifest, nil
}
