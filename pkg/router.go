package rbacinjector

import (
	"context"
	"net/http"
)

// NewHttpRouter returns a new HttpRouter.
// The HttpRouter is used to configure the server.
// The HttpRouter is an HTTP request multiplexer.
func NewHttpRouter[T RoleID](roleExtractor RoleExtractor[T]) (*HttpRouter[T], error) {
	r := &HttpRouter[T]{
		roleExtractor:            roleExtractor,
		forbiddenResponseFunc:    func(w http.ResponseWriter, _ context.Context) { w.WriteHeader(http.StatusForbidden) },
		unauthorizedResponseFunc: func(w http.ResponseWriter, _ context.Context) { w.WriteHeader(http.StatusUnauthorized) },
		ServeMux:                 http.NewServeMux(),
	}
	return r, nil
}

// HttpRouter is an HTTP request multiplexer.
type HttpRouter[T RoleID] struct {
	roleExtractor            RoleExtractor[T]
	forbiddenResponseFunc    ErrorResponseFunc
	unauthorizedResponseFunc ErrorResponseFunc
	*http.ServeMux
}

// SetForbiddenResponseFunc sets the function that is called when the role is not contained in the roles.
func (r *HttpRouter[T]) SetForbiddenResponseFunc(f ErrorResponseFunc) {
	r.forbiddenResponseFunc = f
}

// SetUnauthorizedResponseFunc sets the function that is called when the role is not found.
func (r *HttpRouter[T]) SetUnauthorizedResponseFunc(f ErrorResponseFunc) {
	r.unauthorizedResponseFunc = f
}

// HandleFuncAllowFor registers the handler for the given pattern.
// The handler is called for HTTP requests, if the role is contained in the roles.
func (r *HttpRouter[T]) HandleFuncAllowFor(pattern string, handler http.HandlerFunc, roles ...Role[T]) {
	f := AllowFor[T](
		r.roleExtractor,
		handler,
		r.unauthorizedResponseFunc,
		r.forbiddenResponseFunc,
		roles...,
	)
	r.ServeMux.HandleFunc(pattern, f)
}

// HandleFuncDenyFor registers the handler for the given pattern.
// The handler is called for HTTP requests, if the role is not contained in the roles.
func (r *HttpRouter[T]) HandleFuncDenyFor(pattern string, handler http.HandlerFunc, roles ...Role[T]) {
	f := DenyFor[T](
		r.roleExtractor,
		handler,
		r.unauthorizedResponseFunc,
		r.forbiddenResponseFunc,
		roles...,
	)
	r.ServeMux.HandleFunc(pattern, f)
}

// NewRoute returns a new HttpRoute.
func (r *HttpRouter[T]) NewRoute(path ...string) (HttpRoute[T], error) {
	return newHttpRoute(r, path...)
}

// AllowFor returns a new handler that checks if the role is contained in the roles.
func AllowFor[T RoleID](roleExtractor RoleExtractor[T], handler http.HandlerFunc, unauthorizedResponseFunc ErrorResponseFunc, forbiddenResponseFunc ErrorResponseFunc, roles ...Role[T]) http.HandlerFunc {
	return process[T](true, roleExtractor, handler, unauthorizedResponseFunc, forbiddenResponseFunc, roles...)
}

// DenyFor returns a new handler that checks if the role is not contained in the roles.
func DenyFor[T RoleID](roleExtractor RoleExtractor[T], handler http.HandlerFunc, unauthorizedResponseFunc ErrorResponseFunc, forbiddenResponseFunc ErrorResponseFunc, roles ...Role[T]) http.HandlerFunc {
	return process[T](false, roleExtractor, handler, unauthorizedResponseFunc, forbiddenResponseFunc, roles...)
}

// process returns a new handler that checks if the role is contained in the roles.
func process[T RoleID](
	expected bool,
	roleExtractor RoleExtractor[T],
	handler http.HandlerFunc,
	unauthorizedResponseFunc ErrorResponseFunc,
	forbiddenResponseFunc ErrorResponseFunc,
	roles ...Role[T],
) http.HandlerFunc {
	validator := newRoleValidator(roles)
	return func(w http.ResponseWriter, r *http.Request) {
		if role, exists := roleExtractor(r); !exists || role == nil {
			unauthorizedResponseFunc(w, r.Context())
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if validator.IN(role.ID()) != expected {
			forbiddenResponseFunc(w, r.Context())
			w.WriteHeader(http.StatusForbidden)
			return
		}
		handler(w, r)
	}
}

// ErrorResponseFunc is a function that writes an error response.
type ErrorResponseFunc func(w http.ResponseWriter, ctx context.Context)
