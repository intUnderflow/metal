package handlers

import (
	"github.com/intunderflow/metal/broker/go/lib"
	"github.com/intunderflow/metal/wrapper"
	"net/http"
)

func NewGetConfig(wrapper *wrapper.ConfigWrapper) GetConfig {
	return GetConfig{
		wrapper: wrapper,
	}
}

type GetConfig struct {
	wrapper *wrapper.ConfigWrapper
}

func (h GetConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.wrapper.Mutex.RLock()
	defer h.wrapper.Mutex.RUnlock()

	return lib.RespondWithJSON(h.wrapper.Config, w)
}
