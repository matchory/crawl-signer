package extproc

import (
	"context"
	"errors"
	"io"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/matchory/crawl-signer/internal/config"
	"github.com/matchory/crawl-signer/internal/robots"
	"github.com/matchory/crawl-signer/internal/rules"
	"github.com/matchory/crawl-signer/internal/whois"
)

type fakeStream struct {
	grpc.ServerStream
	in  []*extprocv3.ProcessingRequest
	out []*extprocv3.ProcessingResponse
}

func (f *fakeStream) Context() context.Context { return context.Background() }

func (f *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(f.in) == 0 {
		return nil, io.EOF
	}
	r := f.in[0]
	f.in = f.in[1:]
	return r, nil
}

func (f *fakeStream) Send(r *extprocv3.ProcessingResponse) error {
	f.out = append(f.out, r)
	return nil
}

type robotsCall struct {
	origin robots.Origin
	path   string
}

type fakeRobots struct {
	mu      sync.Mutex
	outcome robots.Outcome
	calls   []robotsCall
	wait    time.Duration
	paced   []robots.Origin
}

func (f *fakeRobots) Check(_ context.Context, o robots.Origin, path string) robots.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, robotsCall{o, path})
	return f.outcome
}

func (f *fakeRobots) Pace(o robots.Origin) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paced = append(f.paced, o)
	return f.wait
}

type fakeSigner struct {
	err   error
	empty bool
	calls []string
}

func (f *fakeSigner) Headers(_ context.Context, authority string) ([]rules.Header, error) {
	f.calls = append(f.calls, authority)
	if f.err != nil || f.empty {
		return nil, f.err
	}
	return []rules.Header{
		{Name: "Signature-Agent", Value: `"https://bot.example.com"`},
		{Name: "Signature-Input", Value: "sig1=(...)"},
		{Name: "Signature", Value: "sig1=:" + authority + ":"},
	}, nil
}

type fakeWhois struct {
	caller whois.Caller
	err    error
	calls  []netip.Addr
}

func (f *fakeWhois) Lookup(_ context.Context, a netip.Addr) (whois.Caller, error) {
	f.calls = append(f.calls, a)
	return f.caller, f.err
}

var cfg = config.Config{
	UserAgent: "Mozilla/5.0 (compatible; ExampleBot/1.0)", From: "bot@example.com",
	SigningKey: config.SigningKey{KeyID: "K"},
}

type fixture struct {
	robots *fakeRobots
	signer *fakeSigner
	whois  *fakeWhois
	srv    *Server
}

func newFixture() *fixture {
	f := &fixture{
		robots: &fakeRobots{outcome: robots.Allowed},
		signer: &fakeSigner{},
		whois: &fakeWhois{
			caller: whois.Caller{Node: "worker-1", Tags: []string{"tag:example-crawler"}},
		},
	}
	f.srv = New(cfg, f.robots, f.robots, f.signer, f.whois)
	return f
}

// callerAddr is a source.address in the form Envoy sends for a TCP caller,
// address and port, as the end-to-end test sees it ("127.0.0.1:33232").
const callerAddr = "100.101.102.103:54321"

// request builds a request-headers message; source "-" omits the source.address attribute.
func request(source string, kv ...string) *extprocv3.ProcessingRequest {
	base := map[string]string{
		":method":    "GET",
		":scheme":    "http",
		":authority": "example.com",
		":path":      "/a",
	}
	var hs []*corev3.HeaderValue
	for i := 0; i < len(kv); i += 2 {
		if _, ok := base[kv[i]]; ok {
			base[kv[i]] = kv[i+1]
			continue
		}
		hs = append(hs, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	for _, k := range []string{":path", ":authority", ":scheme", ":method"} {
		hs = append([]*corev3.HeaderValue{{Key: k, RawValue: []byte(base[k])}}, hs...)
	}
	r := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{
			Headers:     &corev3.HeaderMap{Headers: hs},
			EndOfStream: true,
		},
	}}
	if source != "-" {
		r.Attributes = map[string]*structpb.Struct{
			"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
				"source.address": structpb.NewStringValue(source),
			}},
		}
	}
	return r
}

// withAttribute sets the request attribute name of r to v.
func withAttribute(
	r *extprocv3.ProcessingRequest,
	name string,
	v *structpb.Value,
) *extprocv3.ProcessingRequest {
	if r.Attributes == nil {
		r.Attributes = map[string]*structpb.Struct{
			"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{}},
		}
	}
	r.Attributes["envoy.filters.http.ext_proc"].Fields[name] = v
	return r
}

// internalListener marks r as arriving on Envoy's internal listener, as
// Envoy 1.39 and 1.40 send it: the expression, evaluated to a bool.
func internalListener(r *extprocv3.ProcessingRequest) *extprocv3.ProcessingRequest {
	return withAttribute(r, InternalAttribute, structpb.NewBoolValue(true))
}

func (f *fixture) run(t *testing.T, r *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	t.Helper()
	s := &fakeStream{in: []*extprocv3.ProcessingRequest{r}}
	if err := f.srv.Process(s); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(s.out) != 1 {
		t.Fatalf("got %d responses, want 1", len(s.out))
	}
	return s.out[0]
}

func meta(t *testing.T, r *extprocv3.ProcessingResponse) map[string]*structpb.Value {
	t.Helper()
	ns := r.GetDynamicMetadata().GetFields()["crawl"].GetStructValue()
	if ns == nil {
		t.Fatalf("no crawl metadata in %v", r)
	}
	return ns.GetFields()
}

func assertRefusal(t *testing.T, r *extprocv3.ProcessingResponse, status int, reason string) {
	t.Helper()
	ir := r.GetImmediateResponse()
	if ir == nil {
		t.Fatalf("want immediate response %d %s, got %v", status, reason, r)
	}
	if int(ir.GetStatus().GetCode()) != status {
		t.Errorf("status: got %d, want %d", ir.GetStatus().GetCode(), status)
	}
	var got string
	for _, h := range ir.GetHeaders().GetSetHeaders() {
		if strings.EqualFold(h.GetHeader().GetKey(), "X-Crawl-Gateway-Refusal") {
			got = string(h.GetHeader().GetRawValue())
		}
	}
	if got != reason {
		t.Errorf("refusal header: got %q, want %q", got, reason)
	}
	if v := meta(t, r)["verdict"].GetStringValue(); v != reason {
		t.Errorf("verdict: got %q, want %q", v, reason)
	}
}

func mutation(
	t *testing.T,
	r *extprocv3.ProcessingResponse,
) (map[string]string, []string) {
	t.Helper()
	cr := r.GetRequestHeaders().GetResponse()
	if cr == nil || cr.GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("want CONTINUE request-headers response, got %v", r)
	}
	set := map[string]string{}
	for _, h := range cr.GetHeaderMutation().GetSetHeaders() {
		if h.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Errorf("%s: append action %v", h.GetHeader().GetKey(), h.GetAppendAction())
		}
		set[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	remove := slices.Clone(cr.GetHeaderMutation().GetRemoveHeaders())
	sort.Strings(remove)
	return set, remove
}

// Guards: G2
func TestRefusal(t *testing.T) {
	f := newFixture()
	r := f.run(t, request(callerAddr, ":method", "POST"))
	assertRefusal(t, r, 405, "method")
	if len(f.robots.calls)+len(f.signer.calls) != 0 {
		t.Error("a refused request reached robots or the signer")
	}
}

// Guards: G1, G3
func TestRobotsRefusal(t *testing.T) {
	for _, c := range []struct {
		outcome robots.Outcome
		reason  string
	}{{robots.Disallowed, "robots"}, {robots.Unavailable, "robots-unavailable"}} {
		f := newFixture()
		f.robots.outcome = c.outcome
		r := f.run(t, request(callerAddr))
		assertRefusal(t, r, 403, c.reason)
		if len(f.signer.calls) != 0 {
			t.Errorf("%s: signed a refused request", c.reason)
		}
	}
}

// Guards: G1, G8
func TestCrawlDelayRefusal(t *testing.T) {
	for _, c := range []struct {
		wait  time.Duration
		retry string
	}{{10 * time.Second, "10"}, {1500 * time.Millisecond, "2"}, {time.Millisecond, "1"}} {
		f := newFixture()
		f.robots.wait = c.wait
		r := f.run(t, request(callerAddr))
		assertRefusal(t, r, 429, "crawl-delay")
		var got string
		for _, h := range r.GetImmediateResponse().GetHeaders().GetSetHeaders() {
			switch k := h.GetHeader().GetKey(); k {
			case "retry-after":
				got = string(h.GetHeader().GetRawValue())
			case refusalHeader:
			default:
				t.Errorf("wait %v: the refusal sets %s", c.wait, k)
			}
		}
		if got != c.retry {
			t.Errorf("wait %v: retry-after %q, want %q", c.wait, got, c.retry)
		}
	}
}

// Guards: G8
//
// Only a request that goes out takes a slot, and internal fetches take none.
func TestPaceOnlyAllowed(t *testing.T) {
	for _, outcome := range []robots.Outcome{robots.Disallowed, robots.Unavailable} {
		f := newFixture()
		f.robots.outcome = outcome
		f.run(t, request(callerAddr))
		if len(f.robots.paced) != 0 {
			t.Errorf("%v: paced", outcome)
		}
	}
	f := newFixture()
	f.run(t, internalListener(request("-", ":path", "/robots.txt")))
	if len(f.robots.paced) != 0 {
		t.Error("internal request paced")
	}
	// A request refused after robots.txt, for signing, sent nothing.
	f = newFixture()
	f.signer.err = errors.New("transit down")
	f.run(t, request(callerAddr))
	if len(f.robots.paced) != 0 {
		t.Error("a request refused for signing took a slot")
	}

	f = newFixture()
	f.run(t, request(callerAddr, ":authority", "Example.com"))
	want := []robots.Origin{{Scheme: "https", Authority: "example.com"}}
	if !slices.Equal(f.robots.paced, want) {
		t.Errorf("paced %v, want %v", f.robots.paced, want)
	}
}

// Guards: G1
func TestSigningRefusal(t *testing.T) {
	f := newFixture()
	f.signer.err = errors.New("transit down")
	assertRefusal(t, f.run(t, request(callerAddr)), 503, "signing")

	f = newFixture()
	f.signer.empty = true
	assertRefusal(t, f.run(t, request(callerAddr)), 503, "signing")
}

func TestSchemeHeader(t *testing.T) {
	for _, v := range []string{"https", "ftp", ""} {
		f := newFixture()
		assertRefusal(t, f.run(t, request(callerAddr, "x-crawl-scheme", v)), 403, "scheme")
	}
}

// Guards: G4
func TestAllowedMutation(t *testing.T) {
	f := newFixture()
	r := f.run(t, request(callerAddr,
		"host", "example.com", "accept", "text/html", "range", "bytes=0-1", "cookie", "a=b",
		"user-agent", "curl/8", "from", "me@example.org", "signature", "forged",
		"x-forwarded-for", "1.2.3.4", "x-crawl-upstream", "http", "content-length", "0",
		"x-forwarded-proto", "http"))
	set, remove := mutation(t, r)
	want := map[string]string{
		"user-agent":      cfg.UserAgent,
		"from":            cfg.From,
		"signature-agent": `"https://bot.example.com"`,
		"signature-input": "sig1=(...)",
		"signature":       "sig1=:example.com:",
	}
	if !maps.Equal(set, want) {
		t.Errorf("set: got %v, want %v", set, want)
	}
	if w := []string{
		"content-length",
		"cookie",
		"x-crawl-upstream",
		"x-forwarded-for",
	}; !slices.Equal(
		remove,
		w,
	) {
		t.Errorf("remove: got %v, want %v", remove, w)
	}
	if !r.GetRequestHeaders().GetResponse().GetClearRouteCache() {
		t.Error("route cache not cleared")
	}
	if f.robots.calls[0] != (robotsCall{robots.Origin{Scheme: "https", Authority: "example.com"}, "/a"}) {
		t.Errorf("robots: %+v", f.robots.calls)
	}
	m := meta(t, r)
	if m["verdict"].GetStringValue() != "ok" || m["robots"].GetStringValue() != "allowed" ||
		m["keyid"].GetStringValue() != "K" {
		t.Errorf("metadata: %v", m)
	}
}

func TestPlainHTTP(t *testing.T) {
	f := newFixture()
	r := f.run(t, request(callerAddr, "X-Crawl-Scheme", "http"))
	set, remove := mutation(t, r)
	if set["x-crawl-upstream"] != "http" {
		t.Errorf("x-crawl-upstream not set: %v", set)
	}
	if !slices.Contains(remove, "x-crawl-scheme") {
		t.Errorf("x-crawl-scheme not removed: %v", remove)
	}
	if f.robots.calls[0].origin.Scheme != "http" {
		t.Errorf("robots origin: %+v", f.robots.calls[0])
	}
	// The scheme decides the default port: :80 is fine for http, :443 is not.
	f = newFixture()
	assertRefusal(
		t,
		f.run(t, request(callerAddr, "x-crawl-scheme", "http", ":authority", "example.com:443")),
		403,
		"port",
	)
}

// Guards: G5
func TestAuthorityFromPseudoHeader(t *testing.T) {
	f := newFixture()
	f.run(
		t,
		request(
			callerAddr,
			":authority",
			"A.Example:443",
			"host",
			"b.example",
			":path",
			"/x%2Fy/../z?q=1",
		),
	)
	want := robotsCall{robots.Origin{Scheme: "https", Authority: "a.example"}, "/x%2Fy/../z?q=1"}
	if len(f.robots.calls) != 1 || f.robots.calls[0] != want {
		t.Errorf("robots: got %+v, want %+v", f.robots.calls, want)
	}
	if !slices.Equal(f.signer.calls, []string{"a.example"}) {
		t.Errorf("signed for %v, want a.example", f.signer.calls)
	}

	// Envoy forwards a trailing dot, so the signature keeps it; robots does not.
	f = newFixture()
	f.run(t, request(callerAddr, ":authority", "A.Example.:443"))
	if f.robots.calls[0].origin.Authority != "a.example" ||
		!slices.Equal(f.signer.calls, []string{"a.example."}) {
		t.Errorf("robots %+v, signed for %v", f.robots.calls, f.signer.calls)
	}
}

func TestCaller(t *testing.T) {
	f := newFixture()
	m := meta(t, f.run(t, request(callerAddr)))
	if len(f.whois.calls) != 1 || f.whois.calls[0] != netip.MustParseAddr("100.101.102.103") {
		t.Errorf("whois: %v", f.whois.calls)
	}
	tags := m["caller_tags"].GetListValue().AsSlice()
	if m["caller"].GetStringValue() != "worker-1" || len(tags) != 1 ||
		tags[0] != "tag:example-crawler" {
		t.Errorf("metadata: %v", m)
	}

	f = newFixture()
	f.whois.err = errors.New("no such peer")
	r := f.run(t, request(callerAddr))
	mutation(t, r)
	if c := meta(t, r)["caller"].GetStringValue(); c != "unknown" {
		t.Errorf("caller on whois error: %q", c)
	}

	// Without a whois source, every caller is unknown.
	f = newFixture()
	f.srv = New(cfg, f.robots, f.robots, f.signer, nil)
	r = f.run(t, request(callerAddr))
	mutation(t, r)
	if c := meta(t, r)["caller"].GetStringValue(); c != "unknown" {
		t.Errorf("caller without whois: %q", c)
	}

	// A refusal still names the caller.
	f = newFixture()
	if c := meta(t, f.run(t, request(callerAddr, ":method", "PUT")))["caller"].GetStringValue(); c != "worker-1" {
		t.Errorf("caller on refusal: %q", c)
	}
}

// Guards: G7
func TestInternalListener(t *testing.T) {
	for _, src := range []string{"-", "", "/run/envoy/internal.sock"} {
		f := newFixture()
		f.robots.outcome = robots.Disallowed
		r := f.run(
			t,
			internalListener(request(src, ":path", "/elsewhere/robots.txt", "cookie", "x")),
		)
		_, remove := mutation(t, r)
		if len(f.robots.calls) != 0 || len(f.whois.calls) != 0 {
			t.Errorf("%q: robots %v, whois %v", src, f.robots.calls, f.whois.calls)
		}
		if !slices.Equal(f.signer.calls, []string{"example.com"}) ||
			!slices.Contains(remove, "cookie") {
			t.Errorf("%q: signer %v, remove %v", src, f.signer.calls, remove)
		}
		m := meta(t, r)
		if m["caller"].GetStringValue() != "internal" || m["robots"].GetStringValue() != "skipped" {
			t.Errorf("%q: metadata %v", src, m)
		}
	}

	// Static rules still apply to the signer's own fetches.
	f := newFixture()
	assertRefusal(
		t,
		f.run(t, internalListener(request("", ":authority", "127.0.0.1"))),
		403,
		"target",
	)
}

func TestIPv6Literal(t *testing.T) {
	f := newFixture()
	mutation(t, f.run(t, request(callerAddr, ":authority", "[2001:DB8::1]:443")))
	if f.robots.calls[0].origin.Authority != "[2001:db8::1]" ||
		!slices.Equal(f.signer.calls, []string{"[2001:db8::1]"}) {
		t.Errorf("robots %+v, signed for %v", f.robots.calls, f.signer.calls)
	}
}

func TestEmptyPortRefused(t *testing.T) {
	f := newFixture()
	assertRefusal(t, f.run(t, request(callerAddr, ":authority", "example.com:")), 403, "target")
	if len(f.signer.calls)+len(f.robots.calls) != 0 {
		t.Error("an empty port reached robots or the signer")
	}
}

// Guards: G7
func TestOnlyListenerMetadataMakesInternal(t *testing.T) {
	for _, src := range []string{"-", "", "/run/envoy/internal.sock", "envoy://internal_client_address/"} {
		f := newFixture()
		r := f.run(t, request(src))
		mutation(t, r)
		if len(f.robots.calls) != 1 {
			t.Errorf("%q: robots skipped without listener metadata", src)
		}
		if c := meta(t, r)["caller"].GetStringValue(); c != "unknown" {
			t.Errorf("%q: caller %q", src, c)
		}
	}

	// Only InternalAttribute as the boolean true marks a request internal;
	// the whole listener metadata, as Envoy dumps it to text, doesn't.
	for _, c := range []struct {
		name, attr string
		v          *structpb.Value
	}{
		{"string true", InternalAttribute, structpb.NewStringValue("true")},
		{"false", InternalAttribute, structpb.NewBoolValue(false)},
		{"metadata dump", "xds.listener_metadata", structpb.NewStringValue(
			`filter_metadata { key: "crawl" value { fields { key: "internal" value { bool_value: true } } } } `,
		)},
	} {
		f := newFixture()
		f.run(t, withAttribute(request(callerAddr), c.attr, c.v))
		if len(f.robots.calls) != 1 {
			t.Errorf("%s: skipped robots", c.name)
		}
	}
}

// Guards: G6
func TestVerdictCounter(t *testing.T) {
	f := newFixture()
	var got []string
	f.srv.Count = func(v string) { got = append(got, v) }
	f.run(t, request(callerAddr))
	f.run(t, request(callerAddr, ":method", "POST"))
	if !slices.Equal(got, []string{"ok", "method"}) {
		t.Errorf("counted %v", got)
	}
}

func TestOtherPhasesContinue(t *testing.T) {
	f := newFixture()
	s := &fakeStream{
		in: []*extprocv3.ProcessingRequest{{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{},
		}}},
	}
	if err := f.srv.Process(s); err != nil {
		t.Fatal(err)
	}
	if len(s.out) != 1 || s.out[0].GetResponseHeaders() == nil {
		t.Errorf("got %v", s.out)
	}
}
