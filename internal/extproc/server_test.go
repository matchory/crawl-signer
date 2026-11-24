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
}

func (f *fakeRobots) Check(_ context.Context, o robots.Origin, path string) robots.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, robotsCall{o, path})
	return f.outcome
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
		{Name: "Signature-Agent", Value: `sig1="https://crawler.matchory.net"`},
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
	UserAgent: "Mozilla/5.0 (compatible; MatchoryBot/1.0)", From: "crawler@matchory.com",
	KeyID: "K", KeyVersion: 3,
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
		whois:  &fakeWhois{caller: whois.Caller{Node: "whale-1", Tags: []string{"tag:crawler"}}},
	}
	f.srv = New(cfg, f.robots, f.signer, f.whois)
	return f
}

const callerAddr = "100.101.102.103:54321"

// request builds a request-headers message; source "-" omits the source.address attribute.
func request(source string, kv ...string) *extprocv3.ProcessingRequest {
	base := map[string]string{":method": "GET", ":scheme": "http", ":authority": "example.com", ":path": "/a"}
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
		RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hs}, EndOfStream: true},
	}}
	if source != "-" {
		r.Attributes = map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"source.address": structpb.NewStringValue(source),
		}}}
	}
	return r
}

// internalListener marks r as arriving on Envoy's internal listener.
func internalListener(r *extprocv3.ProcessingRequest) *extprocv3.ProcessingRequest {
	md, err := structpb.NewStruct(map[string]any{"filter_metadata": map[string]any{"crawl": map[string]any{"internal": true}}})
	if err != nil {
		panic(err)
	}
	if r.Attributes == nil {
		r.Attributes = map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{}}}
	}
	r.Attributes["envoy.filters.http.ext_proc"].Fields["xds.listener_metadata"] = structpb.NewStructValue(md)
	return r
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

func mutation(t *testing.T, r *extprocv3.ProcessingResponse) (set map[string]string, remove []string) {
	t.Helper()
	cr := r.GetRequestHeaders().GetResponse()
	if cr == nil || cr.GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("want CONTINUE request-headers response, got %v", r)
	}
	set = map[string]string{}
	for _, h := range cr.GetHeaderMutation().GetSetHeaders() {
		if h.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Errorf("%s: append action %v", h.GetHeader().GetKey(), h.GetAppendAction())
		}
		set[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	remove = slices.Clone(cr.GetHeaderMutation().GetRemoveHeaders())
	sort.Strings(remove)
	return set, remove
}

func TestRefusal(t *testing.T) {
	f := newFixture()
	r := f.run(t, request(callerAddr, ":method", "POST"))
	assertRefusal(t, r, 405, "method")
	if len(f.robots.calls)+len(f.signer.calls) != 0 {
		t.Error("a refused request reached robots or the signer")
	}
}

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

func TestAllowedMutation(t *testing.T) {
	f := newFixture()
	r := f.run(t, request(callerAddr,
		"host", "example.com", "accept", "text/html", "range", "bytes=0-1", "cookie", "a=b",
		"user-agent", "curl/8", "from", "me@example.org", "signature", "forged",
		"x-forwarded-for", "1.2.3.4", "x-crawl-upstream", "http", "content-length", "0"))
	set, remove := mutation(t, r)
	want := map[string]string{
		"user-agent":      cfg.UserAgent,
		"from":            cfg.From,
		"signature-agent": `sig1="https://crawler.matchory.net"`,
		"signature-input": "sig1=(...)",
		"signature":       "sig1=:example.com:",
	}
	if !maps.Equal(set, want) {
		t.Errorf("set: got %v, want %v", set, want)
	}
	if w := []string{"content-length", "cookie", "x-crawl-upstream", "x-forwarded-for"}; !slices.Equal(remove, w) {
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
		m["keyid"].GetStringValue() != "K" || m["key_version"].GetNumberValue() != 3 {
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
	assertRefusal(t, f.run(t, request(callerAddr, "x-crawl-scheme", "http", ":authority", "example.com:443")), 403, "port")
}

func TestAuthorityFromPseudoHeader(t *testing.T) {
	f := newFixture()
	f.run(t, request(callerAddr, ":authority", "A.Example:443", "host", "b.example", ":path", "/x%2Fy/../z?q=1"))
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
	if f.robots.calls[0].origin.Authority != "a.example" || !slices.Equal(f.signer.calls, []string{"a.example."}) {
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
	if m["caller"].GetStringValue() != "whale-1" || len(tags) != 1 || tags[0] != "tag:crawler" {
		t.Errorf("metadata: %v", m)
	}

	f = newFixture()
	f.whois.err = errors.New("no such peer")
	r := f.run(t, request(callerAddr))
	mutation(t, r)
	if c := meta(t, r)["caller"].GetStringValue(); c != "unknown" {
		t.Errorf("caller on whois error: %q", c)
	}

	// A refusal still names the caller.
	f = newFixture()
	if c := meta(t, f.run(t, request(callerAddr, ":method", "PUT")))["caller"].GetStringValue(); c != "whale-1" {
		t.Errorf("caller on refusal: %q", c)
	}
}

func TestInternalListener(t *testing.T) {
	for _, src := range []string{"-", "", "/run/envoy/internal.sock"} {
		f := newFixture()
		f.robots.outcome = robots.Disallowed
		r := f.run(t, internalListener(request(src, ":path", "/elsewhere/robots.txt", "cookie", "x")))
		_, remove := mutation(t, r)
		if len(f.robots.calls) != 0 || len(f.whois.calls) != 0 {
			t.Errorf("%q: robots %v, whois %v", src, f.robots.calls, f.whois.calls)
		}
		if !slices.Equal(f.signer.calls, []string{"example.com"}) || !slices.Contains(remove, "cookie") {
			t.Errorf("%q: signer %v, remove %v", src, f.signer.calls, remove)
		}
		m := meta(t, r)
		if m["caller"].GetStringValue() != "internal" || m["robots"].GetStringValue() != "skipped" {
			t.Errorf("%q: metadata %v", src, m)
		}
	}

	// Static rules still apply to the signer's own fetches.
	f := newFixture()
	assertRefusal(t, f.run(t, internalListener(request("", ":authority", "127.0.0.1"))), 403, "target")
}

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

	// internal must be the boolean true.
	f := newFixture()
	r := request(callerAddr)
	md, _ := structpb.NewStruct(map[string]any{"filter_metadata": map[string]any{"crawl": map[string]any{"internal": "true"}}})
	r.Attributes["envoy.filters.http.ext_proc"].Fields["xds.listener_metadata"] = structpb.NewStructValue(md)
	f.run(t, r)
	if len(f.robots.calls) != 1 {
		t.Error("a string internal skipped robots")
	}
}

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
	s := &fakeStream{in: []*extprocv3.ProcessingRequest{{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{},
	}}}}
	if err := f.srv.Process(s); err != nil {
		t.Fatal(err)
	}
	if len(s.out) != 1 || s.out[0].GetResponseHeaders() == nil {
		t.Errorf("got %v", s.out)
	}
}
