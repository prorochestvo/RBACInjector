package rbacinjector

import (
	"bytes"
	"github.com/twinj/uuid"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHttpRoute_NextRoute(t *testing.T) {
	router, err := NewHttpRouter[uint64](extractorINT)
	if err != nil {
		t.Fatal(err)
	}

	ok := false

	var routeLevel0 *httpRoute[uint64] = nil
	if r, err := newHttpRoute[uint64](router); err != nil {
		t.Fatal(err)
	} else if routeLevel0, ok = r.(*httpRoute[uint64]); !ok {
		t.Fatalf("could not cast to httpRoute[uint64]")
	}

	var routeLevel1 *httpRoute[uint64] = nil
	if r, err := routeLevel0.NextRoute("level", "1"); err != nil {
		t.Fatal(err)
	} else if routeLevel1, ok = r.(*httpRoute[uint64]); !ok {
		t.Fatalf("could not cast to httpRoute[uint64]")
	}

	var routeLevel2 *httpRoute[uint64] = nil
	if r, err := routeLevel1.NextRoute("level", "2"); err != nil {
		t.Fatal(err)
	} else if routeLevel2, ok = r.(*httpRoute[uint64]); !ok {
		t.Fatalf("could not cast to httpRoute[uint64]")
	}

	if routeLevel0.urlPrefix == routeLevel1.urlPrefix {
		t.Fatalf("incorrect route url: %s | %s", routeLevel0.urlPrefix, routeLevel1.urlPrefix)
	}
	if routeLevel0.urlPrefix == routeLevel2.urlPrefix {
		t.Fatalf("incorrect route url: %s | %s", routeLevel0.urlPrefix, routeLevel2.urlPrefix)
	}
	if routeLevel1.urlPrefix == routeLevel2.urlPrefix {
		t.Fatalf("incorrect route url: %s | %s", routeLevel1.urlPrefix, routeLevel2.urlPrefix)
	}

	if !strings.HasPrefix(routeLevel1.urlPrefix, routeLevel0.urlPrefix) {
		t.Fatalf("incorrect route url, not contains prefix: %s | %s", routeLevel1.urlPrefix, routeLevel0.urlPrefix)
	}
	if !strings.HasPrefix(routeLevel2.urlPrefix, routeLevel1.urlPrefix) {
		t.Fatalf("incorrect route url, not contains prefix: %s | %s", routeLevel2.urlPrefix, routeLevel1.urlPrefix)
	}

	if routeLevel0.server != router {
		t.Fatalf("incorrect server: %v | %v", routeLevel0.server, router)
	}
	if routeLevel1.server != router {
		t.Fatalf("incorrect server: %v | %v", routeLevel1.server, router)
	}
	if routeLevel2.server != router {
		t.Fatalf("incorrect server: %v | %v", routeLevel2.server, router)
	}
}

func TestHttpRoute_MethodHandleFunc(t *testing.T) {
	payloadLevel1 := uuid.NewV4().String()
	payloadLevel2 := uuid.NewV4().String()
	router, err := NewHttpRouter[uint64](extractorINT)
	if err != nil {
		t.Fatal(err)
	}

	root, err := newHttpRoute[uint64](router)
	if err != nil {
		t.Fatal(err)
	}

	r1, err := root.NextRoute("demo", "1")
	if err != nil {
		t.Fatal(err)
	}

	r2, err := root.NextRoute("level", "1")
	if err != nil {
		t.Fatal(err)
	}

	root.HandleFuncMethod(stubStatusNotImplementedHandle)
	r1.HandleFuncMethod(stubStatusOKHandle, http.MethodGet)
	r2.HandleFuncMethod(stubStatusOKHandle, http.MethodPost)

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, r1.Url(), bytes.NewBufferString(payloadLevel1))
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code: %d", res.Code)
	}
	if s := res.Body.String(); s != payloadLevel1 {
		t.Errorf("incorrect response body: %s", s)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/"+uuid.NewV4().String(), bytes.NewBufferString(uuid.NewV4().String()))
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNotImplemented {
		t.Errorf("incorrect response code: %d", res.Code)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, r2.Url(), bytes.NewBufferString(payloadLevel2))
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code: %d", res.Code)
	}
	if s := res.Body.String(); s != payloadLevel2 {
		t.Errorf("incorrect response body: %s", s)
	}

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/"+uuid.NewV4().String(), bytes.NewBufferString(uuid.NewV4().String()))
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNotImplemented {
		t.Errorf("incorrect response code: %d", res.Code)
	}
}

func TestHttpRoute_AllowFor(t *testing.T) {
	t.Skipf("not implemented")
}

func TestHttpRoute_DenyFor(t *testing.T) {
	t.Skipf("not implemented")
}

func stubStatusOKHandle(w http.ResponseWriter, r *http.Request) {
	defer func(closer io.ReadCloser) {
		err := closer.Close()
		if err != nil {
			log.Printf("could not close request body; details: %s;", err.Error())
		}
	}(r.Body)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func stubStatusNotImplementedHandle(w http.ResponseWriter, r *http.Request) {
	defer func(closer io.ReadCloser) {
		err := closer.Close()
		if err != nil {
			log.Printf("could not close request body; details: %s;", err.Error())
		}
	}(r.Body)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write(b)
}
