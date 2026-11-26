package rules

import (
	"net/netip"
	"strings"
	"testing"
)

// Guards: G2
//
// FuzzCheck: an authority the rules accept names a hostname or a public
// address, on the scheme's default port. The oracle is net/netip's own
// classification, not the rules' prefix list.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		"example.com", "example.com:443", "127.0.0.1", "[::1]", "[::ffff:10.0.0.1]", "0x7f.1",
		"2130706433", "localhost", "a.localhost.", "[fe80::1%25eth0]", "user@example.com",
		"[2001:db8::1]:443", "100.64.0.1", "169.254.169.254", "[64:ff9b::a00:1]",
	} {
		f.Add(s, true)
	}

	f.Fuzz(func(t *testing.T, authority string, https bool) {
		scheme, port := "http", "80"
		if https {
			scheme, port = "https", "443"
		}

		v := Check(Request{Method: "GET", Scheme: scheme, Authority: authority})
		if !v.OK {
			return
		}

		host, gotPort, ok := parseAuthority(authority)
		if !ok {
			t.Fatalf("accepted %q, which parseAuthority refuses", authority)
		}

		if gotPort != "" && gotPort != port {
			t.Fatalf("accepted %q on port %s for %s", authority, gotPort, scheme)
		}

		if strings.ContainsAny(authority, "@ \t\r\n") {
			t.Fatalf("accepted %q", authority)
		}

		lower := strings.ToLower(strings.TrimSuffix(host, "."))
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
			t.Fatalf("accepted %q, a localhost name", authority)
		}

		addr, err := netip.ParseAddr(host)
		if err != nil {
			return
		}

		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() {
			t.Fatalf("accepted %q, which is not a public address", authority)
		}
	})
}
