package rbacinjector

import (
	"net/http"
	"net/url"
	"strings"
)

type HttpRoute[T RoleID] interface {
	Url() string
	NextRoute(path ...string) (HttpRoute[T], error)
	HandleFuncMethod(handler http.HandlerFunc, methods ...string)
	HandleFuncAllowFor(method string, handler http.HandlerFunc, roles ...Role[T])
	HandleFuncDenyFor(method string, handler http.HandlerFunc, roles ...Role[T])
}

type httpRoute[T RoleID] struct {
	urlPrefix string
	server    *HttpRouter[T]
}

func newHttpRoute[T RoleID](server *HttpRouter[T], prefixes ...string) (HttpRoute[T], error) {
	urlPath, err := url.JoinPath("/", prefixes...)
	if err != nil {
		return nil, err
	}

	r := &httpRoute[T]{
		urlPrefix: urlPath,
		server:    server,
	}
	return r, nil
}

func (r *httpRoute[T]) NextRoute(path ...string) (HttpRoute[T], error) {
	urlPath, err := url.JoinPath(r.urlPrefix, path...)
	if err != nil {
		return nil, err
	}
	nextRoute := &httpRoute[T]{urlPrefix: urlPath, server: r.server}
	return nextRoute, nil
}

func (r *httpRoute[T]) Url() string {
	return r.urlPrefix
}

func (r *httpRoute[T]) HandleFuncMethod(handler http.HandlerFunc, methods ...string) {
	if len(methods) > 0 {
		for _, method := range methods {
			r.server.ServeMux.HandleFunc(strings.TrimSpace(method+" "+r.urlPrefix), handler)
		}
	} else {
		r.server.ServeMux.HandleFunc(strings.TrimSpace(r.urlPrefix), handler)
	}
}

func (r *httpRoute[T]) HandleFuncAllowFor(method string, handler http.HandlerFunc, roles ...Role[T]) {
	r.server.HandleFuncAllowFor(strings.TrimSpace(method+" "+r.urlPrefix), handler, roles...)
}

func (r *httpRoute[T]) HandleFuncDenyFor(method string, handler http.HandlerFunc, roles ...Role[T]) {
	r.server.HandleFuncDenyFor(strings.TrimSpace(method+" "+r.urlPrefix), handler, roles...)
}
