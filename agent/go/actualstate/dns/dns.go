package dns

import (
	"fmt"
	"github.com/intunderflow/metal/config"
	"os"
	"strings"
	"sync"
	"time"
)

type DNS interface {
	ApplySpec(*config.DNSSpec) error
	GetCurrentlyAppliedSpec() *config.DNSSpec
}

func NewDNS(hostsFilePath string) DNS {
	return &dnsImpl{
		hostsFilePath:        hostsFilePath,
		currentlyAppliedSpec: nil,
		mutex:                &sync.RWMutex{},
	}
}

type dnsImpl struct {
	hostsFilePath        string
	currentlyAppliedSpec *config.DNSSpec
	mutex                *sync.RWMutex
}

func (d *dnsImpl) ApplySpec(dnsSpec *config.DNSSpec) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	currentHostFileContents, err := os.ReadFile(d.hostsFilePath)
	if err != nil {
		return err
	}
	var includedLines []string
	inMetalEntries := false
	for _, line := range strings.Split(string(currentHostFileContents), "\n") {
		if strings.HasPrefix(line, "# Begin metal DNS entries") {
			inMetalEntries = true
		} else if strings.HasPrefix("# End metal DNS entries", line) {
			inMetalEntries = false
		} else if !inMetalEntries {
			includedLines = append(includedLines, line)
		}
	}
	includedLines = append(includedLines, "# Begin metal DNS entries "+time.Now().String())
	if dnsSpec != nil {
		for dnsName, ip := range dnsSpec.Entries {
			includedLines = append(includedLines, fmt.Sprintf("%s\t%s", ip, dnsName))
		}
	}
	includedLines = append(includedLines, "# End metal DNS entries")

	newHostFile := []byte(strings.Join(includedLines, "\n"))
	err = os.WriteFile(d.hostsFilePath, newHostFile, 0600)
	if err != nil {
		return err
	}

	d.currentlyAppliedSpec = dnsSpec
	return nil
}

func (d *dnsImpl) GetCurrentlyAppliedSpec() *config.DNSSpec {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.currentlyAppliedSpec
}
