// Package robots decides whether robots.txt (RFC 9309) lets MatchoryBot fetch
// a path, fetching and caching each origin's file.
package robots

import (
	"sort"
	"strings"

	"github.com/jimsmart/grobotstxt"
)

// Agent is the product token MatchoryBot looks for in User-agent lines.
const Agent = "MatchoryBot"

// grobotstxt's matcher only answers one URL per parse, so its parser callbacks
// collect the selected group's rules and grobotstxt.Matches matches them.

// ruleOverhead approximates the per-rule bytes beyond the pattern itself.
const ruleOverhead = 32

// rulesOverhead approximates the bytes of an entry with no rules, so even an
// allow-all entry counts toward the cache bound.
const rulesOverhead = 64

type rule struct {
	pattern string
	allow   bool
}

// Rules is the compiled rule list of the group that applies to one agent,
// ordered so the first match is the decision: longest pattern first, allow
// before disallow on equal length.
type Rules struct {
	rules []rule
}

// Parse selects the group for agent (or * if no group names it) and compiles
// its rules.
func Parse(body []byte, agent string) Rules {
	h := &collector{agent: agent}
	grobotstxt.Parse(string(body), h)
	rs := h.global
	if h.everSpecific {
		rs = h.specific
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if len(rs[i].pattern) != len(rs[j].pattern) {
			return len(rs[i].pattern) > len(rs[j].pattern)
		}
		return rs[i].allow && !rs[j].allow
	})
	return Rules{rules: rs}
}

// Allowed reports whether path (with query) may be fetched.
func (r Rules) Allowed(path string) bool {
	if path == "" {
		path = "/"
	}
	for _, rl := range r.rules {
		if matches(path, rl.pattern) {
			return rl.allow
		}
	}
	return true
}

// Size approximates the memory the rules hold, in bytes.
func (r Rules) Size() int {
	n := rulesOverhead
	for _, rl := range r.rules {
		n += len(rl.pattern) + ruleOverhead
	}
	return n
}

func matches(path, pattern string) bool {
	if !strings.ContainsAny(pattern, "*$") {
		return strings.HasPrefix(path, pattern)
	}
	return grobotstxt.Matches(path, pattern)
}

// collector mirrors grobotstxt.RobotsMatcher's group tracking, keeping the
// rules instead of matching one path.
type collector struct {
	agent                         string
	inGlobal, inSpecific, sawRule bool
	everSpecific                  bool
	global, specific              []rule
}

func (c *collector) HandleRobotsStart() {}
func (c *collector) HandleRobotsEnd()   {}

func (c *collector) HandleUserAgent(_ int, ua string) {
	if c.sawRule {
		c.inGlobal, c.inSpecific, c.sawRule = false, false, false
	}
	if ua == "*" || (strings.HasPrefix(ua, "*") && isSpace(ua[1])) {
		c.inGlobal = true
		return
	}
	if strings.EqualFold(token(ua), c.agent) {
		c.inSpecific, c.everSpecific = true, true
	}
}

func (c *collector) HandleAllow(_ int, v string)    { c.add(v, true) }
func (c *collector) HandleDisallow(_ int, v string) { c.add(v, false) }

func (c *collector) add(pattern string, allow bool) {
	if !c.inGlobal && !c.inSpecific {
		return
	}
	c.sawRule = true
	// An empty pattern matches nothing (RFC 9309 2.2.2).
	if pattern == "" {
		return
	}
	r := rule{pattern: pattern, allow: allow}
	if c.inSpecific {
		c.specific = append(c.specific, r)
	} else {
		c.global = append(c.global, r)
	}
}

func (c *collector) HandleSitemap(int, string)               {}
func (c *collector) HandleUnknownAction(int, string, string) {}

// token cuts a User-agent value at the first character outside an RFC 9110
// token, so "MatchoryBot/1.0" names MatchoryBot.
func token(ua string) string {
	for i := 0; i < len(ua); i++ {
		c := ua[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return ua[:i]
		}
	}
	return ua
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }
