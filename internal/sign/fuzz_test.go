package sign

import (
	"strings"
	"testing"
)

// Guards: G5
//
// FuzzSignatureAuthority: whatever authority a caller sends, the
// signature base has exactly its three lines, so a caller can't make the
// signature cover anything but the authority the request goes to.
func FuzzSignatureAuthority(f *testing.F) {
	for _, s := range []string{
		"example.com", "Example.COM.:443", "[2001:db8::1]:443", "a b", "a\nb", "x\r\n\"@authority\": y",
		"bücher.de", ":443", "[::1",
	} {
		f.Add(s, true)
	}

	f.Fuzz(func(t *testing.T, authority string, https bool) {
		scheme := "http"
		if https {
			scheme = "https"
		}

		a := SignatureAuthority(scheme, authority)
		if a == "" {
			return
		}

		for _, r := range a {
			if r <= ' ' || r >= 0x7f {
				t.Fatalf("%q gives @authority %q, with %q", authority, a, r)
			}
		}

		if a != strings.ToLower(a) {
			t.Fatalf("%q gives @authority %q, not lowercase", authority, a)
		}

		base, _ := Base(a, Agent{URL: "https://bot.example.com"}, "K", 1, 2)
		if n := strings.Count(base, "\n"); n != 2 {
			t.Fatalf("%q gives a signature base of %d lines", authority, n+1)
		}
	})
}

// FuzzCanonicalAuthority: canonicalising twice changes nothing, so one site
// has one cache entry however its name is spelt.
func FuzzCanonicalAuthority(f *testing.F) {
	for _, s := range []string{"Example.com.:443", "bücher.de", "[2001:DB8::1]:8443", "a..b", "xn--bcher-kva.de"} {
		f.Add(s, true)
	}

	f.Fuzz(func(t *testing.T, authority string, https bool) {
		scheme := "http"
		if https {
			scheme = "https"
		}

		c := CanonicalAuthority(scheme, authority)
		if c == "" {
			return
		}

		if again := CanonicalAuthority(scheme, c); again != c {
			t.Fatalf("%q -> %q -> %q", authority, c, again)
		}
	})
}
