package rbacinjector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	iRoleRoot     = stubRoleINT(0x8000000000000000)
	iRoleAdmin    = stubRoleINT(0x0000000000000002)
	iRoleCustomer = stubRoleINT(0x0000000000000010)
	iRoleGuest    = stubRoleINT(0x0000000000000000)
)

func TestAllowForUINT64(t *testing.T) {
	f := AllowFor[uint64](extractorINT, httpStatusNoContent, errorUnauthorized, errorForbidden, iRoleCustomer, iRoleAdmin)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleAdmin))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleRoot))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	f(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "unauthorized" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleCustomer))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}
}

func TestDenyForUINT64(t *testing.T) {
	f := DenyFor[uint64](extractorINT, httpStatusNoContent, errorUnauthorized, errorForbidden, iRoleCustomer, iRoleAdmin)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleAdmin))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleRoot))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	f(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "unauthorized" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleCustomer))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}
}

func TestProcessRoleUINT64(t *testing.T) {
	f := process[uint64](true, extractorINT, httpStatusNoContent, errorUnauthorized, errorForbidden, iRoleCustomer, iRoleAdmin)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/process", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleAdmin))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/process", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleRoot))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/process", nil)
	f(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "unauthorized" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/process", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, iRoleCustomer))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}
}

// 2024-06-16: BenchmarkProcessINT-8            2751499               432.8 ns/op           928 B/op         14 allocs/op
func BenchmarkProcessINT(b *testing.B) {
	f := process[uint64](true, extractorINT, httpStatusNoContent, errorUnauthorized, errorForbidden, iRoleCustomer, iRoleAdmin, iRoleGuest)

	reqAdmin := httptest.NewRequest("GET", "/process", nil)
	reqAdmin = reqAdmin.WithContext(context.WithValue(reqAdmin.Context(), contextRoleKey, iRoleAdmin))

	reqRoot := httptest.NewRequest("GET", "/process", nil)
	reqRoot = reqRoot.WithContext(context.WithValue(reqRoot.Context(), contextRoleKey, iRoleRoot))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		f(httptest.NewRecorder(), reqAdmin)
		f(httptest.NewRecorder(), reqRoot)
	}
}

const (
	sRoleRoot     = stubRoleSTR("ROOT")
	sRoleAdmin    = stubRoleSTR("ADMIN")
	sRoleCustomer = stubRoleSTR("CUSTOMER")
	sRoleGuest    = stubRoleSTR("GUEST")
)

func TestAllowForSTRING(t *testing.T) {
	f := AllowFor[string](extractorSTR, httpStatusNoContent, errorUnauthorized, errorForbidden, sRoleCustomer, sRoleAdmin)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleAdmin))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleRoot))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	f(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "unauthorized" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleCustomer))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}
}

func TestDenyForSTRING(t *testing.T) {
	f := DenyFor[string](extractorSTR, httpStatusNoContent, errorUnauthorized, errorForbidden, sRoleCustomer, sRoleAdmin)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleAdmin))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleRoot))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	f(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "unauthorized" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/allow", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleCustomer))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}
}

func TestProcessRoleSTRING(t *testing.T) {
	f := process[string](true, extractorSTR, httpStatusNoContent, errorUnauthorized, errorForbidden, sRoleCustomer, sRoleAdmin)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/process", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleAdmin))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/process", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleRoot))
	f(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "forbidden" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/process", nil)
	f(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code %d", res.Code)
	} else if res.Body.String() != "unauthorized" {
		t.Errorf("unexpected body %s", res.Body.String())
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/process", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextRoleKey, sRoleCustomer))
	f(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("unexpected status code %d", res.Code)
	}
}

// 2024-06-16: BenchmarkProcessSTR-8            2194533               554.3 ns/op           946 B/op         15 allocs/op
func BenchmarkProcessSTR(b *testing.B) {
	f := process[string](true, extractorSTR, httpStatusNoContent, errorUnauthorized, errorForbidden, sRoleCustomer, sRoleAdmin, sRoleGuest)

	reqAdmin := httptest.NewRequest("GET", "/process", nil)
	reqAdmin = reqAdmin.WithContext(context.WithValue(reqAdmin.Context(), contextRoleKey, sRoleAdmin))

	reqRoot := httptest.NewRequest("GET", "/process", nil)
	reqRoot = reqRoot.WithContext(context.WithValue(reqRoot.Context(), contextRoleKey, sRoleRoot))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		f(httptest.NewRecorder(), reqAdmin)
		f(httptest.NewRecorder(), reqRoot)
	}
}

func httpStatusNoContent(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

type stubRoleINT uint64

func (r stubRoleINT) ID() uint64 {
	return uint64(r)
}

type stubRoleSTR string

func (r stubRoleSTR) ID() string {
	return string(r)
}

const contextRoleKey = "role"

func extractorINT(_ http.ResponseWriter, r *http.Request) (role Role[uint64], exists bool) {
	val := r.Context().Value(contextRoleKey)
	role, exists = val.(Role[uint64])
	return
}

func extractorSTR(_ http.ResponseWriter, r *http.Request) (role Role[string], exists bool) {
	val := r.Context().Value(contextRoleKey)
	role, exists = val.(Role[string])
	return
}

func errorUnauthorized(w http.ResponseWriter, _ context.Context) {
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("unauthorized"))
}

func errorForbidden(w http.ResponseWriter, _ context.Context) {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("forbidden"))
}
