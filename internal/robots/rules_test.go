package robots

import "testing"

func TestParse(t *testing.T) {
	for _, c := range []struct {
		name, body string
		allowed    map[string]bool
	}{
		{
			name:    "specific group beats star",
			body:    "User-agent: *\nDisallow: /\n\nUser-agent: ExampleBot\nDisallow: /x\n",
			allowed: map[string]bool{"/a": true, "/x": false, "/x/y": false},
		},
		{
			name:    "star applies without a specific group",
			body:    "User-agent: OtherBot\nDisallow: /\n\nUser-agent: *\nDisallow: /x\n",
			allowed: map[string]bool{"/a": true, "/x": false},
		},
		{
			name:    "longest match wins",
			body:    "User-agent: ExampleBot\nDisallow: /private\nAllow: /private/ok\n",
			allowed: map[string]bool{"/private/ok": true, "/private/ok/deep": true, "/private/x": false, "/public": true},
		},
		{
			name:    "allow wins ties",
			body:    "User-agent: ExampleBot\nDisallow: /same\nAllow: /same\n",
			allowed: map[string]bool{"/same": true},
		},
		{
			name:    "wildcard and end anchor",
			body:    "User-agent: ExampleBot\nDisallow: /*.pdf$\n",
			allowed: map[string]bool{"/a.pdf": false, "/a.pdf?x": true, "/dir/b.pdf": false, "/a.html": true},
		},
		{
			name:    "agent token is case-insensitive",
			body:    "User-agent: examplebot\nDisallow: /\n",
			allowed: map[string]bool{"/": false, "/a": false},
		},
		{
			name:    "empty disallow allows everything",
			body:    "User-agent: ExampleBot\nDisallow:\n",
			allowed: map[string]bool{"/": true, "/a": true},
		},
		{
			name:    "empty file",
			body:    "",
			allowed: map[string]bool{"/": true, "/anything": true},
		},
		{
			name:    "leading BOM is ignored",
			body:    "\xEF\xBB\xBFUser-agent: ExampleBot\nDisallow: /x\n",
			allowed: map[string]bool{"/x": false, "/a": true},
		},
		{
			name:    "HTML page",
			body:    "<!doctype html><html><body>Not found</body></html>",
			allowed: map[string]bool{"/": true, "/a": true},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := Parse([]byte(c.body), agent)
			for path, want := range c.allowed {
				if got := r.Allowed(path); got != want {
					t.Errorf("Allowed(%q) = %v, want %v", path, got, want)
				}
			}
		})
	}
}

func TestRulesSize(t *testing.T) {
	empty := Parse(nil, agent).Size()
	one := Parse([]byte("User-agent: *\nDisallow: /abc\n"), agent).Size()
	if empty <= 0 || one <= empty {
		t.Fatalf("Size: empty %d, one rule %d", empty, one)
	}
}

const agent = "ExampleBot"
