// Package robots decides whether robots.txt (RFC 9309) lets the crawler fetch
// a path, fetching and caching each origin's file.
package robots

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jimsmart/grobotstxt"
)

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

// delayLimit bounds a parsed Crawl-delay so that converting it can't overflow.
const delayLimit = 24 * time.Hour

// Rules is the compiled rule list of the group that applies to one agent,
// ordered so the first match is the decision: longest pattern first, allow
// before disallow on equal length.
type Rules struct {
	rules []rule
	// Delay is the group's Crawl-delay, zero without one. RFC 9309 doesn't
	// define it; it is read as seconds between requests, as Bing and Yandex do.
	Delay time.Duration
}

// Parse selects the group for agent (or * if no group names it) and compiles
// its rules.
func Parse(body []byte, agent string) Rules {
	h := &collector{agent: agent}
	grobotstxt.Parse(string(body), h)
	rs, delay := h.global, h.globalDelay
	if h.everSpecific {
		rs, delay = h.specific, h.specificDelay
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if len(rs[i].pattern) != len(rs[j].pattern) {
			return len(rs[i].pattern) > len(rs[j].pattern)
		}
		return rs[i].allow && !rs[j].allow
	})
	return Rules{rules: rs, Delay: delay}
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
	globalDelay, specificDelay    time.Duration
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

func (c *collector) HandleSitemap(int, string) {}

// HandleUnknownAction reads Crawl-delay, which grobotstxt doesn't know. It
// doesn't end a group, as in Google's parser, and the largest value wins.
func (c *collector) HandleUnknownAction(_ int, action, value string) {
	if !strings.EqualFold(action, "crawl-delay") || (!c.inGlobal && !c.inSpecific) {
		return
	}
	s, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(s) || math.IsInf(s, 0) || s <= 0 {
		return
	}
	d := delayLimit
	if s < delayLimit.Seconds() {
		d = time.Duration(s * float64(time.Second))
	}
	if c.inSpecific {
		c.specificDelay = max(c.specificDelay, d)
	} else {
		c.globalDelay = max(c.globalDelay, d)
	}
}

// token cuts a User-agent value at the first character outside an RFC 9110
// token, so "ExampleBot/1.0" names ExampleBot.
func token(ua string) string {
	for i := range len(ua) {
		if c := ua[i]; !tokenChar(c) {
			return ua[:i]
		}
	}
	return ua
}

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

func tokenChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }
