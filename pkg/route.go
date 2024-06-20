package rbacinjector

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type HttpRoute[T RoleID] interface {
	Url() string
	NextRoute(urlSuffix ...string) (HttpRoute[T], error)
	HandleFuncMethod(handler http.HandlerFunc, methods ...string)
	AllowFor(method string, handler http.HandlerFunc, roles ...Role[T])
	DenyFor(method string, handler http.HandlerFunc, roles ...Role[T])
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

func (r *httpRoute[T]) NextRoute(urlSuffix ...string) (HttpRoute[T], error) {
	urlPath, err := url.JoinPath(r.urlPrefix, urlSuffix...)
	if err != nil {
		return nil, err
	}
	nextRoute := &httpRoute[T]{urlPrefix: urlPath, server: r.server}
	return nextRoute, nil
}

func (r *httpRoute[T]) Url() string {
	return r.urlPrefix
}

func (r *httpRoute[T]) HandleFuncMethod(handler http.HandlerFunc, method ...string) {
	if len(method) > 0 {
		for _, m := range method {
			r.server.ServeMux.HandleFunc(r.pattern(m, r.urlPrefix), handler)
		}
	} else {
		r.server.ServeMux.HandleFunc(r.pattern("", r.urlPrefix), handler)
	}
}

func (r *httpRoute[T]) AllowFor(method string, handler http.HandlerFunc, roles ...Role[T]) {
	r.server.HandleFuncAllowFor(r.pattern(method, r.urlPrefix), handler, roles...)
}

func (r *httpRoute[T]) DenyFor(method string, handler http.HandlerFunc, roles ...Role[T]) {
	r.DenyFor(method, handler, roles...)
}

func (r *httpRoute[T]) pattern(method, urlPath string) string {
	return strings.TrimSpace(fmt.Sprintf("%s %s", method, urlPath))
}
