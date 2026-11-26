package extproc

import (
	"slices"
	"strings"
	"testing"

	"github.com/matchory/crawl-signer/internal/rules"
)

// Guards: G4
//
// FuzzHeaders: whatever headers a caller sends, a request crawl-signer lets
// through leaves with the gateway's User-Agent and signature, and without
// any header outside the allowlist.
func FuzzHeaders(f *testing.F) {
	f.Add("User-Agent", "spoof", "Signature", "sig1=:AA==:")
	f.Add("cookie", "a=b", "X-Crawl-Upstream", "http")
	f.Add("Accept", "*/*", "authorization", "Bearer x")

	f.Fuzz(func(t *testing.T, n1, v1, n2, v2 string) {
		fx := newFixture()
		r := fx.run(t, request(callerAddr, n1, v1, n2, v2))

		if r.GetRequestHeaders() == nil {
			return
		}

		set, remove := mutation(t, r)
		if set["user-agent"] != cfg.UserAgent || set["signature"] == "" {
			t.Fatalf("headers %q=%q %q=%q: set %v", n1, v1, n2, v2, set)
		}

		for _, name := range []string{n1, n2} {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, ":") || lower == "host" || lower == "x-forwarded-proto" {
				continue
			}

			if keep, _ := rules.Allowlist([]rules.Header{{Name: lower}}); len(keep) == 1 {
				continue
			}

			if _, ok := set[lower]; !ok && !slices.Contains(remove, lower) {
				t.Fatalf(
					"%q is neither allowlisted, set nor removed: set %v, remove %v",
					name,
					set,
					remove,
				)
			}
		}
	})
}
