package wrapper

import (
	"github.com/intunderflow/metal/config"
	"sync"
)

type ConfigWrapper struct {
	Config *config.Config
	Mutex  *sync.RWMutex
}

func NewWrapper(config *config.Config) *ConfigWrapper {
	return &ConfigWrapper{
		Config: config,
		Mutex:  &sync.RWMutex{},
	}
}
