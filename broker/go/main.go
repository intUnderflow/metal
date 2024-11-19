package main

import (
	"crypto/tls"
	"fmt"
	"github.com/intunderflow/metal/broker/go/handlers"
	"github.com/intunderflow/metal/broker/go/lib"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"github.com/intunderflow/metal/wrapper"
	"log"
	"net/http"
	"os"
)

var (
	port        = os.Getenv("PORT")
	rootCAPath  = os.Getenv("ROOT_CA_PATH")
	tlsCertPath = os.Getenv("TLS_CERT_PATH")
	tlsKeyPath  = os.Getenv("TLS_KEY_PATH")
)

func main() {
	currentConfig := config.NewConfig()
	currentWrapper := wrapper.NewWrapper(currentConfig)
	rootCertPool, err := crypto.LoadCertPoolFromFile(rootCAPath)
	if err != nil {
		panic(err)
	}
	verifier, err := crypto.PKIVerifierFromFile(rootCAPath)
	if err != nil {
		panic(err)
	}
	http.Handle("/v1/get_config", lib.NewErrorHandler(handlers.NewGetConfig(currentWrapper)))
	http.Handle("/v1/get_remote_address", lib.NewErrorHandler(handlers.NewGetRemoteAddress()))
	http.Handle("/v1/set_node_actual_state", lib.NewErrorHandler(handlers.NewSetNodeActualState(verifier, currentWrapper)))
	http.Handle("/v1/set_node_goal_state", lib.NewErrorHandler(handlers.NewSetNodeGoalState(verifier, currentWrapper)))
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: logRequest(http.DefaultServeMux),
		TLSConfig: &tls.Config{
			ClientCAs:  rootCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}
	fmt.Printf("Server listening at :%s...\n", port)
	err = server.ListenAndServeTLS(tlsCertPath, tlsKeyPath)
	if err != nil {
		panic(err)
	}
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
