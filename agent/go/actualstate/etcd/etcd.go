package etcd

import (
	"context"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/config"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Etcd interface {
	GetCurrentlyAppliedSpec() *config.EtcdSpec
	ApplySpec(*config.EtcdSpec) error
	CheckHealthy(context.Context) error
	RestartService(context.Context) error
}

func NewEtcd(nodeID string, etcdConfigFilePath string, etcdSystemdName string) Etcd {
	return &etcdImpl{
		mutex:                &sync.RWMutex{},
		nodeID:               nodeID,
		etcdConfigFilePath:   etcdConfigFilePath,
		etcdSystemdName:      etcdSystemdName,
		currentlyAppliedSpec: nil,
		lastRestart:          time.Unix(0, 0),
	}
}

type etcdImpl struct {
	mutex                *sync.RWMutex
	nodeID               string
	etcdConfigFilePath   string
	etcdSystemdName      string
	currentlyAppliedSpec *config.EtcdSpec
	lastRestart          time.Time
}

func (e *etcdImpl) GetCurrentlyAppliedSpec() *config.EtcdSpec {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.currentlyAppliedSpec
}

func (e *etcdImpl) ApplySpec(etcdSpec *config.EtcdSpec) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	fileContents, err := generateEtcdFile(e.nodeID, etcdSpec)
	if err != nil {
		return err
	}
	err = os.WriteFile(e.etcdConfigFilePath, []byte(fileContents), 0600)
	if err != nil {
		return err
	}
	e.currentlyAppliedSpec = etcdSpec
	return nil
}

func (e *etcdImpl) CheckHealthy(ctx context.Context) error {
	command := exec.CommandContext(ctx, "systemctl", "status", e.etcdSystemdName, "--no-pager")
	output, err := command.CombinedOutput()
	if err != nil {
		return err
	}
	if strings.Contains(string(output), "active (running)") || strings.Contains(string(output), "status=0/SUCCESS") {
		return nil
	}
	return errors.New(string(output))
}

func (e *etcdImpl) RestartService(ctx context.Context) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	e.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", e.etcdSystemdName).Run()
}

func generateEtcdFile(nodeID string, etcdSpec *config.EtcdSpec) (string, error) {
	var initialCluster []string
	for id, peer := range etcdSpec.Peers {
		initialCluster = append(initialCluster, fmt.Sprintf("%s=%s", id, peer.PeerEndpoint))
	}

	var selfPeer *config.EtcdPeer
	for id, entry := range etcdSpec.Peers {
		if id == nodeID {
			selfPeer = &entry
			break
		}
	}
	if selfPeer == nil {
		return "", errors.New("could not find own peer to get advertise and listen urls")
	}

	return fmt.Sprintf(
		"name: %s\n"+
			"initial-cluster: %s\n"+
			"listen-peer-urls: %s\n"+
			"initial-advertise-peer-urls: %s\n"+
			"listen-client-urls: %s\n"+
			"advertise-client-urls: %s\n"+
			"initial-cluster-state: 'new'",
		etcdSpec.Name,
		strings.Join(initialCluster, ","),
		selfPeer.PeerEndpoint,
		selfPeer.PeerEndpoint,
		selfPeer.ClientEndpoint,
		selfPeer.ClientEndpoint,
	), nil
}
