package rbacinjector

import (
	"net/http"
	"strings"
)

// HttpRoute is an HTTP request multiplexer for as part of specific URL.
type HttpRoute[T RoleID] interface {
	Url() string
	NextRoute(path ...string) (HttpRoute[T], error)
	HandleFunc(pattern string, handler http.HandlerFunc) error
	HandleFuncAllowFor(pattern string, handler http.HandlerFunc, roles ...Role[T]) error
	HandleFuncDenyFor(pattern string, handler http.HandlerFunc, roles ...Role[T]) error
}

// httpRoute is a struct that implements the HttpRoute interface.
type httpRoute[T RoleID] struct {
	urlPrefix string
	server    *HttpRouter[T]
}

func newHttpRoute[T RoleID](server *HttpRouter[T], p ...string) (HttpRoute[T], error) {
	path := "/" + strings.Join(p, "/")
	path = strings.ReplaceAll(path, "//", "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}

	r := &httpRoute[T]{
		urlPrefix: strings.TrimSpace(path),
		server:    server,
	}
	return r, nil
}

func (r *httpRoute[T]) NextRoute(p ...string) (HttpRoute[T], error) {
	path := r.urlPrefix + "/" + strings.Join(p, "/")
	path = strings.ReplaceAll(path, "//", "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	nextRoute := &httpRoute[T]{urlPrefix: path, server: r.server}
	return nextRoute, nil
}

func (r *httpRoute[T]) Url() string {
	return r.urlPrefix
}

func (r *httpRoute[T]) HandleFunc(pattern string, handler http.HandlerFunc) error {
	p, err := r.Pattern(pattern)
	if err != nil {
		return err
	}
	r.server.HandleFunc(p, handler)
	return nil
}

func (r *httpRoute[T]) HandleFuncAllowFor(pattern string, handler http.HandlerFunc, roles ...Role[T]) error {
	p, err := r.Pattern(pattern)
	if err != nil {
		return err
	}
	r.server.HandleFuncAllowFor(p, handler, roles...)
	return nil
}

func (r *httpRoute[T]) HandleFuncDenyFor(pattern string, handler http.HandlerFunc, roles ...Role[T]) error {
	p, err := r.Pattern(pattern)
	if err != nil {
		return err
	}
	r.server.HandleFuncDenyFor(p, handler, roles...)
	return nil
}

func (r *httpRoute[T]) Pattern(pattern ...string) (string, error) {
	// extract method and url path
	method := ""
	path := strings.TrimSpace(strings.Join(pattern, "/"))
	if strings.Contains(path, " ") {
		parts := strings.SplitN(path, " ", 2)
		method = strings.TrimSpace(parts[0])
		path = strings.TrimSpace(parts[1])
	}

	// combine url path
	path = r.urlPrefix + "/" + path
	path = strings.ReplaceAll(path, "//", "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}

	// return final pattern
	return strings.TrimSpace(method + " " + path), nil
}
