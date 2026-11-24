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
	for _, a := range []string{"10.0.0.1", "[fd7a::1]", "169.254.169.254", "localhost", "foo.localhost:443", "[::1]:443",
		"evil@127.0.0.1", "example.com:", "127.1", "0x7f.0.0.1", "2130706433", "017700000001",
		":443", ".", "..", "127.1..", "localhost..", "::1:443",
		"[169.254.169.254].", "[::1].", "[::1]x:443", "[127.0.0.1]x", "[::1]:", "example.com:44a",
		"[::]", "[::]:443", " 127.0.0.1", "127.0.0.1 ", "127.0.0.1\t", "\t127.0.0.1", " localhost", "127.0.0.1\n",
		"10.0.0.1/", "127.0.0.1#", "%31%32%37.0.0.1",
		"[::127.0.0.1]", "[::a9fe:a9fe]", "[64:ff9b::7f00:1]", "[64:ff9b:1::a00:1]", "[2002:7f00:1::1]",
		"[::ffff:127.0.0.1]", "[::ffff:a9fe:a9fe]", "[fe80::1%25eth0]", "LOCALHOST", "foo.localhost.", "0.0.0.0",
		"[0:0:0:0:0:0:0:1]"} {
		if v := Check(req("GET", "https", a)); v != want {
			t.Errorf("%s: got %+v, want %+v", a, v, want)
		}
	}
	if v := Check(req("GET", "https", "93.184.215.14")); !v.OK {
		t.Errorf("public ip: got %+v", v)
	}
}

func TestAllowedAuthorities(t *testing.T) {
	for _, a := range []string{"[2001:db8::1]:443", "example.com.", "example.com.:443",
		"xn--bcher-kva.de", "under_score.example.com"} {
		if v := Check(req("GET", "https", a)); !v.OK {
			t.Errorf("%s: got %+v, want OK", a, v)
		}
	}
}

func TestSchemeCaseInsensitive(t *testing.T) {
	if v := Check(req("GET", "HTTPS", "example.com:443")); !v.OK {
		t.Errorf("HTTPS: got %+v, want OK", v)
	}
}

func TestNonHTTPSchemeIs403Scheme(t *testing.T) {
	want := Verdict{false, 403, "scheme"}
	for _, sc := range []string{"", "ftp", "file"} {
		if v := Check(req("GET", sc, "example.com")); v != want {
			t.Errorf("scheme %q: got %+v, want %+v", sc, v, want)
		}
	}
}

func TestAllowlist(t *testing.T) {
	in := []Header{{"Cookie", "a"}, {"Authorization", "b"}, {"User-Agent", "c"}, {"accept", "d"},
		{"Range", "e"}, {"X-Forwarded-For", "f"}, {"Signature", "g"},
		{"ACCEPT-LANGUAGE", "h"}, {"Accept-Encoding", "i"}, {"If-None-Match", "j"}, {"if-modified-since", "k"}}
	keep, drop := Allowlist(in)
	wantKeep := []Header{{"accept", "d"}, {"Range", "e"}, {"ACCEPT-LANGUAGE", "h"}, {"Accept-Encoding", "i"},
		{"If-None-Match", "j"}, {"if-modified-since", "k"}}
	if !reflect.DeepEqual(keep, wantKeep) {
		t.Errorf("keep = %v, want %v", keep, wantKeep)
	}
	if want := []string{"Cookie", "Authorization", "User-Agent", "X-Forwarded-For", "Signature"}; !reflect.DeepEqual(drop, want) {
		t.Errorf("drop = %v, want %v", drop, want)
	}
}
