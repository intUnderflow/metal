package rollout

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
)

type kubernetesKubeletIssueCertificate struct {
	nodeID         string
	forNodeID      string
	publicKey      string
	pkiService     pki.PKI
	kubeletService kubelet.Kubelet
}

func (k *kubernetesKubeletIssueCertificate) NodeID() string {
	return k.nodeID
}

func (k *kubernetesKubeletIssueCertificate) Apply(_ context.Context) error {
	der, err := base64.StdEncoding.DecodeString(k.publicKey)
	if err != nil {
		return err
	}
	cryptoPublic, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return err
	}

	cert, err := k.pkiService.IssueKubeNodeCertificate(k.forNodeID, cryptoPublic)
	if err != nil {
		return err
	}

	k.kubeletService.AddCertificateForFulfillment(k.forNodeID, base64.StdEncoding.EncodeToString(cert))
	return nil
}

func (k *kubernetesKubeletIssueCertificate) Priority() Priority {
	return Priority{
		Major: 16,
		Minor: 0,
	}
}

func (k *kubernetesKubeletIssueCertificate) BasicDisplayTextForHumans() string {
	return fmt.Sprintf("Issue a certificate to kubelet %s", k.forNodeID)
}

func (k *kubernetesKubeletIssueCertificate) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Need to issue a certificate to node %s with public key %s", k.forNodeID, k.publicKey)
}
