package handlers

import (
	"github.com/intunderflow/metal/broker/go/lib"
	"net"
	"net/http"
)

func NewGetRemoteAddress() GetRemoteAddress {
	return GetRemoteAddress{}
}

type GetRemoteAddress struct{}

type GetRemoteAddressResponse struct {
	RemoteAddress string `json:"remote_address"`
}

func (g GetRemoteAddress) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	// remove port from address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}
	return lib.RespondWithJSON(GetRemoteAddressResponse{
		RemoteAddress: host,
	}, w)
}
