package robots

import (
	"strings"
	"testing"
)

// Guards: G3
//
// FuzzParse: a robots.txt without a single Disallow line allows every path.
// The parser accepts misspellings such as "Disalow" and "Dissallow", as
// Google's does, so the oracle is the absence of "di" altogether.
func FuzzParse(f *testing.F) {
	f.Add("User-agent: *\nDisallow: /private\n", "/private/x")
	f.Add("User-agent: ExampleBot\nAllow: /a$\nDisallow: /*\n", "/a")
	f.Add("\xEF\xBB\xBFuser-agent: examplebot/2\ndisallow: /\n", "/")
	f.Add("User-agent: *\nAllow: /\n", "/%7E")

	f.Fuzz(func(t *testing.T, body, path string) {
		r := Parse([]byte(body), agent)
		allowed := r.Allowed(path)

		if !strings.Contains(strings.ToLower(body), "di") && !allowed {
			t.Fatalf("no Disallow line, yet %q is refused by\n%s", path, body)
		}

		if r.Size() < rulesOverhead {
			t.Fatalf("size %d below the overhead", r.Size())
		}
	})
}

// FuzzDisallowAll: "Disallow: /" for the agent's group, or for every agent,
// refuses every path.
func FuzzDisallowAll(f *testing.F) {
	f.Add("/", "*")
	f.Add("/a?b", agent)

	f.Fuzz(func(t *testing.T, path, group string) {
		if group != "*" {
			group = agent
		}

		if !strings.HasPrefix(path, "/") {
			return
		}

		r := Parse([]byte("User-agent: "+group+"\nDisallow: /\n"), agent)
		if r.Allowed(path) {
			t.Fatalf("Disallow: / for %s, yet %q is allowed", group, path)
		}
	})
}

// FuzzMaxAge: any Cache-Control header gives a lifetime within the bounds
// the cache applies.
func FuzzMaxAge(f *testing.F) {
	for _, s := range []string{"max-age=3600", "public, max-age=\"60\"", "max-age=-1", "MAX-AGE=99999999999999999999"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, v string) {
		d, ok := maxAge([]string{v})
		if d < 0 || d > maxTTL || !ok && d != 0 {
			t.Fatalf("%q: %v, %v", v, d, ok)
		}
	})
}
