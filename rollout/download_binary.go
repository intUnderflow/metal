package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/downloader"
)

type downloadBinary struct {
	nodeID          string
	key             string
	url             string
	expectedHash    string
	downloadService downloader.Downloader
}

func (d *downloadBinary) NodeID() string {
	return d.nodeID
}

func (d *downloadBinary) Apply(_ context.Context) error {
	return d.downloadService.DownloadBinary(d.key, d.url, d.expectedHash)
}

func (d *downloadBinary) Priority() Priority {
	return Priority{
		Major: 0,
		Minor: 0,
	}
}

func (d *downloadBinary) BasicDisplayTextForHumans() string {
	return fmt.Sprintf("Download binary %s", d.key)
}

func (d *downloadBinary) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Download binary %s from URL %s expecting hash %s", d.key, d.url, d.expectedHash)
}
