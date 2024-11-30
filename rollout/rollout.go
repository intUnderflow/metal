package rollout

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/coredns"
	"github.com/intunderflow/metal/agent/go/actualstate/dns"
	"github.com/intunderflow/metal/agent/go/actualstate/downloader"
	"github.com/intunderflow/metal/agent/go/actualstate/etcd"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/apiserver"
	controller_manager "github.com/intunderflow/metal/agent/go/actualstate/kubernetes/controller-manager"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/proxy"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/scheduler"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
	"github.com/intunderflow/metal/agent/go/actualstate/wireguard"
	"github.com/intunderflow/metal/config"
	"math/rand"
	"reflect"
	"sort"
	"strconv"
)

const (
	// Public ports (wireguard, etc) are 60000-61000
	// Private ports (etcd, etc) are 61000-62000
	_etcdPeerPort                          = 61000
	_etdClientPort                         = 61001
	_kubernetesAPIServerSecurePort         = 61100
	_kubernetesControllerManagerSecurePort = 61101
	_kubernetesSchedulerSecurePort         = 61102
	_kubernetesKubeletSecurePort           = 61103

	// _coreDNSPort has to match the default DNS port
	_coreDNSPort = 53

	_clusterCIDR = "10.97.0.0/12"
)

type Rollout interface {
	NodeID() string
	Apply(context.Context) error
	Priority() Priority
	BasicDisplayTextForHumans() string
	DetailedDisplayTextForHumans() string
}

type Priority struct {
	Major int
	Minor int
}

func NewService(wireguardService wireguard.Wireguard, etcdService etcd.Etcd, kubernetesAPIServerService apiserver.ApiServer, kubernetesControllerManagerService controller_manager.ControllerManager, kubernetesSchedulerService scheduler.Scheduler, dnsService dns.DNS, pkiService pki.PKI, kubeletService kubelet.Kubelet, coreDNSService coredns.CoreDNS, kubernetesProxyService proxy.Proxy, downloadService downloader.Downloader) *Service {
	return &Service{
		wireguardService:                   wireguardService,
		etcdService:                        etcdService,
		kubernetesAPIServerService:         kubernetesAPIServerService,
		kubernetesControllerManagerService: kubernetesControllerManagerService,
		kubernetesSchedulerService:         kubernetesSchedulerService,
		dnsService:                         dnsService,
		pkiService:                         pkiService,
		kubeletService:                     kubeletService,
		coreDNSService:                     coreDNSService,
		kubernetesProxyService:             kubernetesProxyService,
		downloadService:                    downloadService,
	}
}

type Service struct {
	wireguardService                   wireguard.Wireguard
	etcdService                        etcd.Etcd
	kubernetesAPIServerService         apiserver.ApiServer
	kubernetesControllerManagerService controller_manager.ControllerManager
	kubernetesSchedulerService         scheduler.Scheduler
	dnsService                         dns.DNS
	pkiService                         pki.PKI
	kubeletService                     kubelet.Kubelet
	coreDNSService                     coredns.CoreDNS
	kubernetesProxyService             proxy.Proxy
	downloadService                    downloader.Downloader
}

func (r *Service) GetRollouts(config *config.Config) ([]Rollout, error) {
	outOfOrder, err := r.getRolloutsOutOfOrder(config)
	if err != nil {
		return nil, err
	}
	return r.orderRollouts(outOfOrder), nil
}

func (r *Service) orderRollouts(rollouts []Rollout) []Rollout {
	sort.Slice(rollouts, func(i, j int) bool {
		rolloutI := rollouts[i]
		rolloutJ := rollouts[j]
		rolloutIPriority := rolloutI.Priority()
		rolloutJPriority := rolloutJ.Priority()
		// Major priority always has precedence
		if rolloutIPriority.Major != rolloutJPriority.Major {
			return rolloutIPriority.Major < rolloutJPriority.Major
		}
		// Nodes have priority based on node ID before minor
		nodeIPriority := getPriorityForNodeID(rolloutI.NodeID())
		nodeJPriority := getPriorityForNodeID(rolloutJ.NodeID())
		if nodeIPriority < nodeJPriority {
			return true
		} else if nodeJPriority < nodeIPriority {
			return false
		}
		// Node priority is the same. Priority is lowest number wins.
		return rolloutIPriority.Minor < rolloutJPriority.Minor
	})

	return rollouts
}

func (r *Service) getRolloutsOutOfOrder(config *config.Config) ([]Rollout, error) {
	var rollouts []Rollout
	for _, node := range config.Nodes {
		nodeRollouts, err := r.getRolloutsForNode(config, node)
		if err != nil {
			return nil, err
		}
		if len(nodeRollouts) > 0 {
			rollouts = append(rollouts, nodeRollouts...)
		}
	}

	return rollouts, nil
}

func (r *Service) getRolloutsForNode(config *config.Config, node *config.Node) ([]Rollout, error) {
	if node.GoalState == nil || node.ActualState == nil {
		return nil, nil
	}

	var rollouts []Rollout

	if node.GoalState.KubernetesAPIServerBinary != "" && !hasBinary(node.ActualState.DownloadedBinaries, "kube-apiserver", node.GoalState.KubernetesAPIServerBinaryHash) {
		rollouts = append(rollouts, &downloadBinary{
			nodeID:          node.GoalState.ID,
			key:             "kube-apiserver",
			url:             node.GoalState.KubernetesAPIServerBinary,
			expectedHash:    node.GoalState.KubernetesAPIServerBinaryHash,
			downloadService: r.downloadService,
		})
	}

	if node.GoalState.KubernetesControllerManagerBinary != "" && !hasBinary(node.ActualState.DownloadedBinaries, "kube-controller-manager", node.GoalState.KubernetesControllerManagerBinaryHash) {
		rollouts = append(rollouts, &downloadBinary{
			nodeID:          node.GoalState.ID,
			key:             "kube-controller-manager",
			url:             node.GoalState.KubernetesControllerManagerBinary,
			expectedHash:    node.GoalState.KubernetesControllerManagerBinaryHash,
			downloadService: r.downloadService,
		})
	}

	if node.GoalState.KubernetesSchedulerBinary != "" && !hasBinary(node.ActualState.DownloadedBinaries, "kube-scheduler", node.GoalState.KubernetesSchedulerBinaryHash) {
		rollouts = append(rollouts, &downloadBinary{
			nodeID:          node.GoalState.ID,
			key:             "kube-scheduler",
			url:             node.GoalState.KubernetesSchedulerBinary,
			expectedHash:    node.GoalState.KubernetesSchedulerBinaryHash,
			downloadService: r.downloadService,
		})
	}

	if node.GoalState.KubernetesKubeletBinary != "" && !hasBinary(node.ActualState.DownloadedBinaries, "kubelet", node.GoalState.KubernetesKubeletBinaryHash) {
		rollouts = append(rollouts, &downloadBinary{
			nodeID:          node.GoalState.ID,
			key:             "kubelet",
			url:             node.GoalState.KubernetesKubeletBinary,
			expectedHash:    node.GoalState.KubernetesKubeletBinaryHash,
			downloadService: r.downloadService,
		})
	}

	if node.GoalState.WireguardMeshMember {
		if node.ActualState.WireguardStatus != "HEALTHY" {
			rollouts = append(rollouts, &wireguardWaitUntilHealthy{
				nodeID:           node.GoalState.ID,
				currentStatus:    node.ActualState.WireguardStatus,
				wireguardService: r.wireguardService,
			})
		}
		expectedSpec := generateWireguardSpec(config, node.GoalState.ID)
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.WireguardSpec) {
			rollouts = append(rollouts, &wireguardConfigApply{
				nodeID:           node.GoalState.ID,
				specToApply:      expectedSpec,
				wireguardService: r.wireguardService,
			})
		}
		expectedDNSSpec := generateDNSSpec(config, node.GoalState.ID)
		if expectedDNSSpec != nil && !reflect.DeepEqual(expectedDNSSpec, node.ActualState.DNSSpec) {
			rollouts = append(rollouts, &dnsConfigApply{
				nodeID:      node.GoalState.ID,
				specToApply: expectedDNSSpec,
				dnsService:  r.dnsService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.WireguardSpec != nil {
			rollouts = append(rollouts, &wireguardConfigApply{
				nodeID:           node.GoalState.ID,
				specToApply:      nil,
				wireguardService: r.wireguardService,
			})
		}
		if node.ActualState != nil && node.ActualState.DNSSpec != nil {
			rollouts = append(rollouts, &dnsConfigApply{
				nodeID:      node.GoalState.ID,
				specToApply: nil,
				dnsService:  r.dnsService,
			})
		}
	}

	if node.GoalState.EtcdMember {
		if node.ActualState.EtcdStatus != "HEALTHY" {
			rollouts = append(rollouts, &etcdWaitUntilHealthy{
				nodeID:        node.GoalState.ID,
				currentStatus: node.ActualState.EtcdStatus,
				etcdService:   r.etcdService,
			})
		}
		expectedSpec, err := generateEtcdSpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.EtcdSpec) {
			rollouts = append(rollouts, &etcdConfigApply{
				nodeID:      node.GoalState.ID,
				specToApply: expectedSpec,
				etcdService: r.etcdService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.EtcdSpec != nil {
			rollouts = append(rollouts, &etcdConfigApply{
				nodeID:      node.GoalState.ID,
				specToApply: nil,
				etcdService: r.etcdService,
			})
		}
	}

	if node.GoalState.KubernetesControlPlane {
		if node.ActualState.KubernetesAPIServerStatus != "HEALTHY" {
			rollouts = append(rollouts, &kubernetesAPIServerWaitUntilHealthy{
				nodeID:                     node.GoalState.ID,
				currentStatus:              node.ActualState.KubernetesAPIServerStatus,
				kubernetesAPIServerService: r.kubernetesAPIServerService,
			})
		}
		expectedSpec, err := generateKubernetesAPIServerSpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.KubernetesAPIServerSpec) {
			rollouts = append(rollouts, &kubernetesAPIServerConfigApply{
				nodeID:                     node.GoalState.ID,
				specToApply:                expectedSpec,
				kubernetesAPIServerService: r.kubernetesAPIServerService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.EtcdSpec != nil {
			rollouts = append(rollouts, &kubernetesAPIServerConfigApply{
				nodeID:                     node.GoalState.ID,
				specToApply:                nil,
				kubernetesAPIServerService: r.kubernetesAPIServerService,
			})
		}
	}

	if node.GoalState.KubernetesControlPlane {
		if node.ActualState.KubernetesControllerManagerStatus != "HEALTHY" {
			rollouts = append(rollouts, &kubernetesControllerManagerWaitUntilHealthy{
				nodeID:                             node.GoalState.ID,
				currentStatus:                      node.ActualState.KubernetesControllerManagerStatus,
				kubernetesControllerManagerService: r.kubernetesControllerManagerService,
			})
		}
		expectedSpec, err := generateKubernetesControllerManagerSpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.KubernetesControllerManagerSpec) {
			rollouts = append(rollouts, &kubernetesControllerManagerConfigApply{
				nodeID:                             node.GoalState.ID,
				specToApply:                        expectedSpec,
				kubernetesControllerManagerService: r.kubernetesControllerManagerService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.KubernetesControllerManagerSpec != nil {
			rollouts = append(rollouts, &kubernetesControllerManagerConfigApply{
				nodeID:                             node.GoalState.ID,
				specToApply:                        nil,
				kubernetesControllerManagerService: r.kubernetesControllerManagerService,
			})
		}
	}

	if node.GoalState.KubernetesControlPlane {
		if node.ActualState.KubernetesSchedulerStatus != "HEALTHY" {
			rollouts = append(rollouts, &kubernetesSchedulerWaitUntilHealthy{
				nodeID:                     node.GoalState.ID,
				currentStatus:              node.ActualState.KubernetesSchedulerStatus,
				kubernetesSchedulerService: r.kubernetesSchedulerService,
			})
		}
		expectedSpec, err := generateKubernetesSchedulerSpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.KubernetesSchedulerSpec) {
			rollouts = append(rollouts, &kubernetesSchedulerConfigApply{
				nodeID:                     node.GoalState.ID,
				specToApply:                expectedSpec,
				kubernetesSchedulerService: r.kubernetesSchedulerService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.KubernetesSchedulerSpec != nil {
			rollouts = append(rollouts, &kubernetesSchedulerConfigApply{
				nodeID:                     node.GoalState.ID,
				specToApply:                nil,
				kubernetesSchedulerService: r.kubernetesSchedulerService,
			})
		}
	}

	if node.GoalState.KubernetesControlPlane {
		if node.ActualState.CoreDNSStatus != "HEALTHY" {
			rollouts = append(rollouts, &coreDNSWaitUntilHealthy{
				nodeID:         node.GoalState.ID,
				currentStatus:  node.ActualState.CoreDNSStatus,
				coreDNSService: r.coreDNSService,
			})
		}
		expectedSpec, err := generateCoreDNSSpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.CoreDNSSpec) {
			rollouts = append(rollouts, &coreDNSConfigApply{
				nodeID:         node.GoalState.ID,
				specToApply:    expectedSpec,
				coreDNSService: r.coreDNSService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.CoreDNSSpec != nil {
			rollouts = append(rollouts, &coreDNSConfigApply{
				nodeID:         node.GoalState.ID,
				specToApply:    nil,
				coreDNSService: r.coreDNSService,
			})
		}
	}

	if node.GoalState.KubernetesWorker {
		if node.ActualState.KubernetesKubeletStatus != nil && node.ActualState.KubernetesKubeletStatus.Status != "HEALTHY" {
			rollouts = append(rollouts, &kubernetesKubeletWaitUntilHealthy{
				nodeID:         node.GoalState.ID,
				currentStatus:  node.ActualState.KubernetesKubeletStatus.Status,
				kubeletService: r.kubeletService,
			})
		}
		expectedSpec, err := generateKubernetesKubeletSpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.KubernetesKubeletSpec) {
			rollouts = append(rollouts, &kubernetesKubeletConfigApply{
				nodeID:         node.GoalState.ID,
				specToApply:    expectedSpec,
				kubeletService: r.kubeletService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.KubernetesKubeletSpec != nil {
			rollouts = append(rollouts, &kubernetesKubeletConfigApply{
				nodeID:         node.GoalState.ID,
				specToApply:    node.ActualState.KubernetesKubeletSpec,
				kubeletService: r.kubeletService,
			})
		}
	}

	if node.GoalState.KubernetesWorker {
		if node.ActualState.KubernetesKubeletStatus != nil && node.ActualState.KubernetesKubeletStatus.CertificateRequest != nil {
			publicKey := node.ActualState.KubernetesKubeletStatus.CertificateRequest.PublicKey
			// Check if fulfilled before making the rollout
			certificate := getCertificateFulfillmentResult(config, node.GoalState.ID)
			if publicKey != "" && certificate == "" {
				nodeToIssue := selectControllerNode(config, node.GoalState.ID)
				if nodeToIssue != "" {
					rollouts = append(rollouts, &kubernetesKubeletIssueCertificate{
						nodeID:         nodeToIssue,
						forNodeID:      node.GoalState.ID,
						publicKey:      publicKey,
						pkiService:     r.pkiService,
						kubeletService: r.kubeletService,
					})
				}
			} else if publicKey != "" && certificate != "" {
				rollouts = append(rollouts, &kubernetesKubeletInstallCertificate{
					nodeID:         node.GoalState.ID,
					certificate:    certificate,
					kubeletService: r.kubeletService,
				})
			}
		}
	}

	if node.GoalState.KubernetesWorker {
		if node.ActualState.KubernetesProxyStatus != "HEALTHY" {
			rollouts = append(rollouts, &kubernetesProxyWaitUntilHealthy{
				nodeID:        node.GoalState.ID,
				currentStatus: node.ActualState.KubernetesProxyStatus,
				proxyService:  r.kubernetesProxyService,
			})
		}
		expectedSpec, err := generateKubernetesProxySpec(config, node.GoalState.ID)
		if err != nil {
			return nil, err
		}
		if expectedSpec != nil && !reflect.DeepEqual(expectedSpec, node.ActualState.KubernetesProxySpec) {
			rollouts = append(rollouts, &kubernetesProxyConfigApply{
				nodeID:       node.GoalState.ID,
				specToApply:  expectedSpec,
				proxyService: r.kubernetesProxyService,
			})
		}
	} else {
		if node.ActualState != nil && node.ActualState.KubernetesProxySpec != nil {
			rollouts = append(rollouts, &kubernetesProxyConfigApply{
				nodeID:       node.GoalState.ID,
				specToApply:  nil,
				proxyService: r.kubernetesProxyService,
			})
		}
	}

	return rollouts, nil
}

func generateWireguardSpec(configToUse *config.Config, nodeID string) *config.WireguardSpec {
	var nodeIDs []string
	for id, _ := range configToUse.Nodes {
		nodeIDs = append(nodeIDs, id)
	}

	sort.Strings(nodeIDs)
	localIPs := deriveIPsForNodes(nodeIDs)
	ports := derivePortsForNodes(nodeIDs)

	var selfPeer config.WireguardPeer
	var peers []config.WireguardPeer
	for _, id := range nodeIDs {
		nodeData := configToUse.Nodes[id]
		if nodeData == nil || nodeData.GoalState == nil || nodeData.ActualState == nil {
			continue
		}
		peer := config.WireguardPeer{
			PeerID:      id,
			Endpoint:    nodeData.ActualState.Endpoint,
			Port:        ports[id],
			PublicKey:   nodeData.ActualState.WireguardPublicKey,
			BindLocalIP: localIPs[id],
		}
		if id == nodeID {
			selfPeer = peer
		} else if validateWireguardPeer(peer) {
			peers = append(peers, peer)
		}
	}

	if len(peers) == 0 {
		return nil
	}

	return &config.WireguardSpec{
		Peers:    peers,
		SelfPeer: selfPeer,
	}
}

func validateWireguardPeer(peer config.WireguardPeer) bool {
	return peer.PeerID != "" && peer.Endpoint != "" && peer.PublicKey != "" && peer.BindLocalIP != ""
}

func generateDNSSpec(configToUse *config.Config, nodeID string) *config.DNSSpec {
	var nodeIDs []string
	for id, _ := range configToUse.Nodes {
		nodeIDs = append(nodeIDs, id)
	}

	sort.Strings(nodeIDs)
	localIPs := deriveIPsForNodes(nodeIDs)

	entries := map[string]string{}
	for id, node := range configToUse.Nodes {
		if node.GoalState != nil && node.GoalState.WireguardMeshMember {
			entries[id+".node.metal.local"] = localIPs[id]
		}
	}

	kubernetesIP := getKubernetesIPForNode(configToUse, nodeID, localIPs)
	if kubernetesIP != "" {
		entries["kubernetes"] = kubernetesIP
		entries["kubernetes.default"] = kubernetesIP
		entries["kubernetes.default.svc"] = kubernetesIP
		entries["kubernetes.default.svc.cluster"] = kubernetesIP
		entries["kubernetes.default.svc.cluster.local"] = kubernetesIP
	}

	return &config.DNSSpec{
		Entries: entries,
	}
}

func getKubernetesIPForNode(configToUse *config.Config, nodeID string, localIPs map[string]string) string {
	node, ok := configToUse.Nodes[nodeID]
	if ok && node.GoalState != nil && node.GoalState.WireguardMeshMember && node.GoalState.KubernetesControlPlane {
		return "127.0.0.1"
	}

	for _, nodeEntry := range configToUse.Nodes {
		if nodeEntry.GoalState != nil && node.GoalState.WireguardMeshMember && node.GoalState.KubernetesControlPlane {
			if ip, ipOk := localIPs[nodeEntry.GoalState.ID]; ipOk {
				return ip
			}
		}
	}

	return ""
}

func generateEtcdSpec(configToUse *config.Config, nodeID string) (*config.EtcdSpec, error) {
	var nodeIDs []string
	for id, _ := range configToUse.Nodes {
		nodeIDs = append(nodeIDs, id)
	}

	sort.Strings(nodeIDs)
	localIPs := deriveIPsForNodes(nodeIDs)

	peers := map[string]config.EtcdPeer{}
	for _, node := range configToUse.Nodes {
		if node.GoalState != nil && node.ActualState != nil && node.GoalState.EtcdMember {
			peers[node.GoalState.ID] = config.EtcdPeer{
				PeerEndpoint:   "http://" + localIPs[node.GoalState.ID] + ":" + strconv.Itoa(_etcdPeerPort),
				ClientEndpoint: "http://" + localIPs[node.GoalState.ID] + ":" + strconv.Itoa(_etdClientPort),
			}
		}
	}

	return &config.EtcdSpec{
		Name:  nodeID,
		Peers: peers,
	}, nil
}

func generateKubernetesAPIServerSpec(configToUse *config.Config, nodeID string) (*config.KubernetesAPIServerSpec, error) {
	node, ok := configToUse.Nodes[nodeID]
	if !ok {
		return nil, nil
	}
	if node.ActualState == nil {
		return nil, nil
	}
	if node.ActualState.WireguardSpec == nil {
		return nil, nil
	}
	localIP := node.ActualState.WireguardSpec.SelfPeer.BindLocalIP

	var etcdServers []string
	etcdSpec, err := generateEtcdSpec(configToUse, nodeID)
	if err != nil {
		return nil, nil
	}
	if etcdSpec == nil {
		return nil, nil
	}
	for _, entry := range etcdSpec.Peers {
		etcdServers = append(etcdServers, entry.ClientEndpoint)
	}
	sort.Strings(etcdServers)

	certificatePEMS := map[string]string{}
	for _, nodeEntry := range configToUse.Nodes {
		if nodeEntry.GoalState != nil && nodeEntry.GoalState.KubernetesControlPlane && nodeEntry.ActualState != nil && nodeEntry.ActualState.KubernetesAPIServerRootCA != "" {
			err = pki.VerifyRootCertificateConformity(nodeEntry.ActualState.KubernetesAPIServerRootCA, nodeEntry.GoalState.ID+".node.metal.local")
			if err != nil {
				return nil, err
			}
			certificatePEMS[nodeEntry.GoalState.ID] = nodeEntry.ActualState.KubernetesAPIServerRootCA
		}
	}

	serviceAccountPublicKeyPEMs := map[string]string{}
	for _, nodeEntry := range configToUse.Nodes {
		if nodeEntry.GoalState != nil && nodeEntry.GoalState.KubernetesControlPlane && nodeEntry.ActualState != nil && nodeEntry.ActualState.KubernetesAPIServerServiceAccountPublicKey != "" {
			err = pki.VerifyPublicKeyWellFormed(nodeEntry.ActualState.KubernetesAPIServerServiceAccountPublicKey)
			if err != nil {
				return nil, err
			}
			serviceAccountPublicKeyPEMs[nodeEntry.GoalState.ID] = nodeEntry.ActualState.KubernetesAPIServerServiceAccountPublicKey
		}
	}

	return &config.KubernetesAPIServerSpec{
		EtcdServers:                 etcdServers,
		AdvertiseAddress:            localIP,
		SecurePort:                  _kubernetesAPIServerSecurePort,
		FeatureGates:                map[string]bool{},
		CertificatePEMs:             certificatePEMS,
		ServiceAccountPublicKeyPEMs: serviceAccountPublicKeyPEMs,
	}, nil
}

func generateKubernetesControllerManagerSpec(configToUse *config.Config, nodeID string) (*config.KubernetesControllerManagerSpec, error) {
	node, ok := configToUse.Nodes[nodeID]
	if !ok {
		return nil, nil
	}
	if node.GoalState == nil {
		return nil, nil
	}
	if node.ActualState == nil {
		return nil, nil
	}
	if node.ActualState.WireguardSpec == nil {
		return nil, nil
	}
	localIP := node.ActualState.WireguardSpec.SelfPeer.BindLocalIP

	return &config.KubernetesControllerManagerSpec{
		ServerAddress:    fmt.Sprintf("https://%s.node.metal.local:%d", node.GoalState.ID, _kubernetesAPIServerSecurePort),
		AdvertiseAddress: localIP,
		SecurePort:       _kubernetesControllerManagerSecurePort,
		ClusterCIDR:      _clusterCIDR,
	}, nil
}

func generateKubernetesSchedulerSpec(configToUse *config.Config, nodeID string) (*config.KubernetesSchedulerSpec, error) {
	node, ok := configToUse.Nodes[nodeID]
	if !ok {
		return nil, nil
	}
	if node.GoalState == nil {
		return nil, nil
	}
	if node.ActualState == nil {
		return nil, nil
	}
	if node.ActualState.WireguardSpec == nil {
		return nil, nil
	}
	localIP := node.ActualState.WireguardSpec.SelfPeer.BindLocalIP

	return &config.KubernetesSchedulerSpec{
		ServerAddress:    fmt.Sprintf("https://%s.node.metal.local:%d", node.GoalState.ID, _kubernetesAPIServerSecurePort),
		AdvertiseAddress: localIP,
		SecurePort:       _kubernetesSchedulerSecurePort,
	}, nil
}

func generateKubernetesKubeletSpec(configToUse *config.Config, nodeID string) (*config.KubernetesKubeletSpec, error) {
	node, ok := configToUse.Nodes[nodeID]
	if !ok {
		return nil, nil
	}
	if node.GoalState == nil {
		return nil, nil
	}
	if node.ActualState == nil {
		return nil, nil
	}
	if node.ActualState.WireguardSpec == nil {
		return nil, nil
	}
	localIP := node.ActualState.WireguardSpec.SelfPeer.BindLocalIP
	var clusterDNS []string

	certificatePEMS := map[string]string{}
	for _, nodeEntry := range configToUse.Nodes {
		if nodeEntry.GoalState != nil && nodeEntry.GoalState.KubernetesControlPlane && nodeEntry.ActualState != nil && nodeEntry.ActualState.KubernetesAPIServerRootCA != "" {
			err := pki.VerifyRootCertificateConformity(nodeEntry.ActualState.KubernetesAPIServerRootCA, nodeEntry.GoalState.ID+".node.metal.local")
			if err != nil {
				return nil, err
			}
			certificatePEMS[nodeEntry.GoalState.ID] = nodeEntry.ActualState.KubernetesAPIServerRootCA
		}
		if nodeEntry.GoalState != nil && nodeEntry.GoalState.KubernetesControlPlane && nodeEntry.ActualState != nil && nodeEntry.ActualState.WireguardSpec != nil {
			clusterDNS = append(clusterDNS, nodeEntry.ActualState.WireguardSpec.SelfPeer.BindLocalIP)
		}
	}

	sort.Strings(clusterDNS)

	apiServerAddress := ""
	nodeSelected := selectControllerNode(configToUse, "kubelet:"+nodeID)
	if nodeSelected != "" {
		apiServerAddress = fmt.Sprintf("https://%s.node.metal.local:%d", nodeSelected, _kubernetesAPIServerSecurePort)
	} else {
		return nil, nil
	}

	return &config.KubernetesKubeletSpec{
		APIServerAddress: apiServerAddress,
		CertificatePEMs:  certificatePEMS,
		KubeletAddress:   localIP,
		SecurePort:       _kubernetesKubeletSecurePort,
		Name:             nodeID,
		ClusterDNS:       clusterDNS,
	}, nil
}

func generateCoreDNSSpec(_ *config.Config, nodeID string) (*config.CoreDNSSpec, error) {
	apiServerAddress := fmt.Sprintf("https://%s.node.metal.local:%d", nodeID, _kubernetesAPIServerSecurePort)
	return &config.CoreDNSSpec{
		Endpoint: apiServerAddress,
		Port:     _coreDNSPort,
	}, nil
}

func generateKubernetesProxySpec(configToUse *config.Config, nodeID string) (*config.KubernetesProxySpec, error) {
	node, ok := configToUse.Nodes[nodeID]
	if !ok {
		return nil, nil
	}
	if node.GoalState == nil {
		return nil, nil
	}
	if node.ActualState == nil {
		return nil, nil
	}
	if node.ActualState.KubernetesKubeletStatus == nil {
		return nil, nil
	}

	return &config.KubernetesProxySpec{
		KubeconfigPath: node.ActualState.KubernetesKubeletStatus.KubeconfigPath,
		ClusterCIDR:    _clusterCIDR,
	}, nil
}

func verifyCertificateConformity(node string, certificate string) error {
	// No need to verify if no certificate is claimed
	if certificate == "" {
		return nil
	}
	// First parse the certificate
	block, rest := pem.Decode([]byte(certificate))
	if len(rest) > 0 {
		return errors.New("only 1 block of PEM data is allowed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	// A certificate must have a subject that matches the node ID, and it must have a name constraint that is critical
	expectedName := node + ".node.metal.local"
	if cert.Subject.CommonName != expectedName {
		return fmt.Errorf("certificate does not match expected name, expected %s, got %s", expectedName, cert.Subject.CommonName)
	}
	if !cert.PermittedDNSDomainsCritical {
		return fmt.Errorf("certificate does not set permitted DNS Domains to be critical")
	}
	if len(cert.PermittedDNSDomains) != 1 {
		return fmt.Errorf("certificate does not set permitted DNS Domains to be exactly 1 value")
	}
	if cert.PermittedDNSDomains[0] != expectedName {
		return fmt.Errorf("certificate permitted DNS names does not match expected name, expected %s, got %s", expectedName, cert.PermittedDNSDomains[0])
	}
	return nil
}

func getCertificateFulfillmentResult(configToUse *config.Config, nodeID string) string {
	for _, node := range configToUse.Nodes {
		if node.GoalState != nil && node.GoalState.KubernetesControlPlane {
			if node.ActualState != nil && node.ActualState.KubernetesKubeletStatus != nil && node.ActualState.KubernetesKubeletStatus.CertificateFulfill != nil {
				cert, ok := node.ActualState.KubernetesKubeletStatus.CertificateFulfill[nodeID]
				if ok {
					return cert
				}
			}
		}
	}
	return ""
}

func selectControllerNode(configToUse *config.Config, source string) string {
	var potentialControllers []string
	for _, node := range configToUse.Nodes {
		if node.GoalState != nil && node.GoalState.KubernetesControlPlane {
			potentialControllers = append(potentialControllers, node.GoalState.ID)
		}
	}
	if len(potentialControllers) == 0 {
		return ""
	}
	sort.Strings(potentialControllers)
	generator := rand.New(rand.NewSource(deriveRandomnessSeedFromString(source)))
	generator.Shuffle(len(potentialControllers), func(i, j int) {
		potentialControllers[i] = potentialControllers[j]
	})
	return potentialControllers[0]
}

func deriveIPsForNodes(nodes []string) map[string]string {
	assignedIPs := map[int]bool{}
	ipsToReturn := map[string]string{}
	for _, node := range nodes {
		generator := rand.New(rand.NewSource(deriveRandomnessSeedFromString(node)))
		ip := 0
		for ip == 0 || assignedIPs[ip] {
			ip = 1 + generator.Intn(250)
		}
		assignedIPs[ip] = true
		ipsToReturn[node] = "10.1.20." + strconv.Itoa(ip)
	}
	return ipsToReturn
}

func derivePortsForNodes(nodes []string) map[string]int {
	result := map[string]int{}
	used := map[int]bool{}
	for _, id := range nodes {
		generator := rand.New(rand.NewSource(deriveRandomnessSeedFromString("node." + id)))
		for {
			// Ports are 60100-60300
			port := generator.Intn(200) + 60100
			if !used[port] {
				used[port] = true
				result[id] = port
				break
			}
		}
	}
	return result
}

func deriveRandomnessSeedFromString(input string) int64 {
	hash := sha256.Sum256([]byte(input))
	return int64(binary.BigEndian.Uint64(hash[:]))
}

func getPriorityForNodeID(nodeID string) int {
	return rand.New(rand.NewSource(deriveRandomnessSeedFromString(nodeID))).Int()
}

func hasBinary(binaries map[string]string, key string, hash string) bool {
	if value, ok := binaries[key]; ok {
		return value == hash
	}
	return false
}
