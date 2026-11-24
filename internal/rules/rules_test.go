package rules

import (
	"reflect"
	"testing"
)

func req(method, scheme, authority string, hs ...Header) Request {
	return Request{Method: method, Scheme: scheme, Authority: authority, Path: "/", Headers: hs}
}

func TestMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD"} {
		if v := Check(req(m, "https", "example.com")); !v.OK {
			t.Errorf("%s: got %+v, want OK", m, v)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "OPTIONS", "CONNECT"} {
		want := Verdict{false, 405, "method"}
		if v := Check(req(m, "https", "example.com")); v != want {
			t.Errorf("%s: got %+v, want %+v", m, v, want)
		}
	}
}

func TestBody(t *testing.T) {
	want := Verdict{false, 413, "body"}
	if v := Check(req("GET", "https", "example.com", Header{"Content-Length", "1"})); v != want {
		t.Errorf("content-length 1: got %+v", v)
	}
	if v := Check(req("GET", "https", "example.com", Header{"content-length", "0"})); !v.OK {
		t.Errorf("content-length 0: got %+v, want OK", v)
	}
	if v := Check(req("GET", "https", "example.com", Header{"transfer-encoding", "chunked"})); v != want {
		t.Errorf("transfer-encoding: got %+v", v)
	}
}

func TestPort(t *testing.T) {
	if v := Check(req("GET", "https", "example.com:443")); !v.OK {
		t.Errorf("443/https: got %+v", v)
	}
	if v := Check(req("GET", "http", "example.com:80")); !v.OK {
		t.Errorf("80/http: got %+v", v)
	}
	want := Verdict{false, 403, "port"}
	if v := Check(req("GET", "https", "example.com:8443")); v != want {
		t.Errorf("8443: got %+v", v)
	}
}

func TestTarget(t *testing.T) {
	want := Verdict{false, 403, "target"}
	for _, a := range []string{"10.0.0.1", "[fd7a::1]", "169.254.169.254", "localhost", "foo.localhost:443", "[::1]:443"} {
		if v := Check(req("GET", "https", a)); v != want {
			t.Errorf("%s: got %+v, want %+v", a, v, want)
		}
	}
	if v := Check(req("GET", "https", "93.184.215.14")); !v.OK {
		t.Errorf("public ip: got %+v", v)
	}
}

func TestAllowlist(t *testing.T) {
	in := []Header{{"Cookie", "a"}, {"Authorization", "b"}, {"User-Agent", "c"}, {"accept", "d"},
		{"Range", "e"}, {"X-Forwarded-For", "f"}, {"Signature", "g"}}
	keep, drop := Allowlist(in)
	if want := []Header{{"accept", "d"}, {"Range", "e"}}; !reflect.DeepEqual(keep, want) {
		t.Errorf("keep = %v, want %v", keep, want)
	}
	if want := []string{"Cookie", "Authorization", "User-Agent", "X-Forwarded-For", "Signature"}; !reflect.DeepEqual(drop, want) {
		t.Errorf("drop = %v, want %v", drop, want)
	}
}
