package rbacinjector

import (
	"net/http"
	"net/url"
	"strings"
)

type HttpRoute[T RoleID] interface {
	Url() string
	NextRoute(path ...string) (HttpRoute[T], error)
	HandleFuncMethod(method string, suffix string, handler http.HandlerFunc) error
	HandleFuncAllowFor(method string, suffix string, handler http.HandlerFunc, roles ...Role[T]) error
	HandleFuncDenyFor(method string, suffix string, handler http.HandlerFunc, roles ...Role[T]) error
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
		urlPrefix: strings.TrimSpace(urlPath),
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

func (r *httpRoute[T]) HandleFuncMethod(method string, suffix string, handler http.HandlerFunc) error {
	path, err := url.JoinPath(r.urlPrefix, strings.TrimSpace(suffix))
	if err != nil {
		return err
	}

	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	pattern := strings.TrimSpace(method + " " + path)

	r.server.HandleFunc(pattern, handler)

	return nil
}

func (r *httpRoute[T]) HandleFuncAllowFor(method string, suffix string, handler http.HandlerFunc, roles ...Role[T]) error {
	path, err := url.JoinPath(r.urlPrefix, suffix)
	if err != nil {
		return err
	}

	r.server.HandleFuncAllowFor(strings.TrimSpace(method+" "+path), handler, roles...)

	return nil
}

func (r *httpRoute[T]) HandleFuncDenyFor(method string, suffix string, handler http.HandlerFunc, roles ...Role[T]) error {
	path, err := url.JoinPath(r.urlPrefix, suffix)
	if err != nil {
		return err
	}

	r.server.HandleFuncDenyFor(strings.TrimSpace(method+" "+path), handler, roles...)

	return nil
}
