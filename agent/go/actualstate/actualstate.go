package actualstate

import (
	"context"
	"github.com/intunderflow/metal/agent/go/actualstate/coredns"
	"github.com/intunderflow/metal/agent/go/actualstate/customrollouts"
	"github.com/intunderflow/metal/agent/go/actualstate/dns"
	"github.com/intunderflow/metal/agent/go/actualstate/downloader"
	"github.com/intunderflow/metal/agent/go/actualstate/endpoint"
	"github.com/intunderflow/metal/agent/go/actualstate/etcd"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/apiserver"
	controller_manager "github.com/intunderflow/metal/agent/go/actualstate/kubernetes/controller-manager"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/proxy"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/scheduler"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
	"github.com/intunderflow/metal/agent/go/actualstate/wireguard"
	"github.com/intunderflow/metal/config"
	"sync"
	"time"
)

type ActualState interface {
	GetActualState(context.Context) (*config.NodeActualState, error)
	SetReconciliationStatus(error)
	InformGoalState(*config.NodeGoalState)
}

func NewActualState(
	id string,
	endpointGetter endpoint.Endpoint,
	wireguardService wireguard.Wireguard,
	etcdService etcd.Etcd,
	kubernetesAPIServerService apiserver.ApiServer,
	kubernetesControllerManagerService controller_manager.ControllerManager,
	kubernetesSchedulerService scheduler.Scheduler,
	dnsService dns.DNS,
	pkiService pki.PKI,
	kubernetesKubeletService kubelet.Kubelet,
	coreDNSService coredns.CoreDNS,
	kubernetesProxyService proxy.Proxy,
	downloadService downloader.Downloader,
	customRolloutsService customrollouts.CustomRollouts,
) ActualState {
	return &actualStateImpl{
		mutex:                              &sync.RWMutex{},
		reconciliationStatus:               "",
		id:                                 id,
		endpointGetter:                     endpointGetter,
		wireguardService:                   wireguardService,
		etcdService:                        etcdService,
		kubernetesAPIServerService:         kubernetesAPIServerService,
		kubernetesControllerManagerService: kubernetesControllerManagerService,
		kubernetesSchedulerService:         kubernetesSchedulerService,
		dnsService:                         dnsService,
		pkiService:                         pkiService,
		kubernetesKubeletService:           kubernetesKubeletService,
		coreDNSService:                     coreDNSService,
		kubernetesProxyService:             kubernetesProxyService,
		downloadService:                    downloadService,
		customRolloutsService:              customRolloutsService,
	}
}

type actualStateImpl struct {
	mutex                              *sync.RWMutex
	reconciliationStatus               string
	id                                 string
	endpointGetter                     endpoint.Endpoint
	wireguardService                   wireguard.Wireguard
	etcdService                        etcd.Etcd
	kubernetesAPIServerService         apiserver.ApiServer
	kubernetesControllerManagerService controller_manager.ControllerManager
	kubernetesSchedulerService         scheduler.Scheduler
	dnsService                         dns.DNS
	pkiService                         pki.PKI
	kubernetesKubeletService           kubelet.Kubelet
	coreDNSService                     coredns.CoreDNS
	kubernetesProxyService             proxy.Proxy
	downloadService                    downloader.Downloader
	customRolloutsService              customrollouts.CustomRollouts
}

func (a *actualStateImpl) GetActualState(ctx context.Context) (*config.NodeActualState, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	currentEndpoint, err := a.endpointGetter.GetEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	wgPublicKey, err := a.wireguardService.GetPublicKey()
	if err != nil {
		return nil, err
	}
	wgSpec := a.wireguardService.GetCurrentlyAppliedSpec()
	etcdSpec := a.etcdService.GetCurrentlyAppliedSpec()
	kubernetesAPIServerSpec := a.kubernetesAPIServerService.GetCurrentlyAppliedSpec()
	kubernetesControllerManagerSpec := a.kubernetesControllerManagerService.GetCurrentlyAppliedSpec()
	kubernetesSchedulerSpec := a.kubernetesSchedulerService.GetCurrentlyAppliedSpec()
	serviceAccountPublicKey, err := a.pkiService.GetServiceAccountPublicKey()
	if err != nil {
		return nil, err
	}
	kubeletStatus, err := a.kubernetesKubeletService.GetStatus(ctx)
	if err != nil {
		return nil, err
	}

	return &config.NodeActualState{
		ID:                        a.id,
		CreatedAt:                 time.Now().UTC(),
		Endpoint:                  currentEndpoint,
		WireguardPublicKey:        wgPublicKey,
		WireguardSpec:             wgSpec,
		WireguardStatus:           deriveServiceHealth(a.wireguardService.CheckHealthy(ctx)),
		DNSSpec:                   a.dnsService.GetCurrentlyAppliedSpec(),
		EtcdSpec:                  etcdSpec,
		EtcdStatus:                deriveServiceHealth(a.etcdService.CheckHealthy(ctx)),
		KubernetesAPIServerSpec:   kubernetesAPIServerSpec,
		KubernetesAPIServerStatus: deriveServiceHealth(a.kubernetesAPIServerService.CheckHealthy(ctx)),
		KubernetesAPIServerRootCA: a.pkiService.GetRootCA(),
		KubernetesAPIServerServiceAccountPublicKey: serviceAccountPublicKey,
		KubernetesControllerManagerSpec:            kubernetesControllerManagerSpec,
		KubernetesControllerManagerStatus:          deriveServiceHealth(a.kubernetesControllerManagerService.CheckHealthy(ctx)),
		KubernetesSchedulerSpec:                    kubernetesSchedulerSpec,
		KubernetesSchedulerStatus:                  deriveServiceHealth(a.kubernetesSchedulerService.CheckHealthy(ctx)),
		KubernetesKubeletSpec:                      a.kubernetesKubeletService.GetCurrentlyAppliedSpec(),
		KubernetesKubeletStatus:                    kubeletStatus,
		CoreDNSSpec:                                a.coreDNSService.GetCurrentlyAppliedSpec(),
		CoreDNSStatus:                              deriveServiceHealth(a.coreDNSService.CheckHealthy(ctx)),
		KubernetesProxySpec:                        a.kubernetesProxyService.GetCurrentlyAppliedSpec(),
		KubernetesProxyStatus:                      deriveServiceHealth(a.kubernetesProxyService.CheckHealthy(ctx)),
		DownloadedBinaries:                         a.downloadService.GetBinariesActualState(),
		CustomRolloutState:                         a.customRolloutsService.GetActualState(ctx),
	}, nil
}

func (a *actualStateImpl) SetReconciliationStatus(reconciliationStatus error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if reconciliationStatus == nil {
		a.reconciliationStatus = ""
	} else {
		a.reconciliationStatus = reconciliationStatus.Error()
	}
}

func (a *actualStateImpl) InformGoalState(goalState *config.NodeGoalState) {
	a.customRolloutsService.SetKnownCustomRollouts(goalState.CustomRolloutSpec)
}

func deriveServiceHealth(err error) string {
	if err == nil {
		return "HEALTHY"
	} else {
		return err.Error()
	}
}
