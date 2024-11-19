package endpoint

import (
	"context"
	"encoding/json"
	"github.com/intunderflow/metal/broker/go/handlers"
	"io"
	"net/http"
	"sync"
)

type Endpoint interface {
	GetEndpoint(context.Context) (string, error)
}

func NewEndpoint(client *http.Client, serverAddress string) Endpoint {
	return &endpointImpl{
		client:                client,
		serverAddress:         serverAddress,
		lastSeenEndpointMutex: &sync.RWMutex{},
		lastSeenEndpoint:      "",
	}
}

type endpointImpl struct {
	client        *http.Client
	serverAddress string

	lastSeenEndpointMutex *sync.RWMutex
	lastSeenEndpoint      string
}

func (e *endpointImpl) GetEndpoint(ctx context.Context) (string, error) {
	remoteEndpoint, err := e.getEndpointRemote(ctx)
	if err != nil {
		// Try and return the last seen endpoint
		e.lastSeenEndpointMutex.RLock()
		defer e.lastSeenEndpointMutex.RUnlock()
		if e.lastSeenEndpoint != "" {
			return e.lastSeenEndpoint, nil
		}
		return "", err
	}
	e.lastSeenEndpointMutex.Lock()
	defer e.lastSeenEndpointMutex.Unlock()
	e.lastSeenEndpoint = remoteEndpoint
	return remoteEndpoint, nil
}

func (e *endpointImpl) getEndpointRemote(ctx context.Context) (string, error) {
	httpResponse, err := e.client.Get(e.serverAddress + "/v1/get_remote_address")
	if err != nil {
		return "", err
	}

	responseBytes, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return "", err
	}

	var response handlers.GetRemoteAddressResponse
	err = json.Unmarshal(responseBytes, &response)
	if err != nil {
		return "", err
	}

	return response.RemoteAddress, nil
}
