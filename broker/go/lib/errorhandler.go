package lib

import "net/http"

type HandlerWithError interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

type ErrorHandler struct {
	underlyingHandler HandlerWithError
}

func NewErrorHandler(handler HandlerWithError) ErrorHandler {
	return ErrorHandler{
		underlyingHandler: handler,
	}
}

func (e ErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := e.underlyingHandler.ServeHTTP(w, r)
	if err != nil {
		HandleError(w, r, err)
	}
}
