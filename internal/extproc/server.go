// Package extproc is the Envoy ext_proc server: one verdict per request, and
// header mutations for the requests it lets through.
package extproc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/matchory/crawl-signer/internal/config"
	"github.com/matchory/crawl-signer/internal/robots"
	"github.com/matchory/crawl-signer/internal/rules"
	"github.com/matchory/crawl-signer/internal/sign"
	"github.com/matchory/crawl-signer/internal/whois"
)

const (
	refusalHeader  = "x-crawl-gateway-refusal"
	schemeHeader   = "x-crawl-scheme"
	upstreamHeader = "x-crawl-upstream"
	namespace      = "crawl"
	schemeHTTP     = "http"
	schemeHTTPS    = "https"
)

// Robots decides whether robots.txt lets the crawler fetch a path;
// *robots.Cache implements it.
type Robots interface {
	Check(ctx context.Context, o robots.Origin, path string) robots.Outcome
}

// Signer returns the signature headers for an authority; *sign.Signer
// implements it.
type Signer interface {
	Headers(ctx context.Context, authority string) ([]rules.Header, error)
}

// Whois names the caller behind an address; *whois.Resolver implements it.
type Whois interface {
	Lookup(ctx context.Context, a netip.Addr) (whois.Caller, error)
}

// Server is Envoy's external processor: one verdict per request.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer

	cfg    config.Config
	robots Robots
	signer Signer
	whois  Whois

	// Count, if set, is called once per request with its verdict.
	Count func(verdict string)
}

// New returns a Server. cfg.SigningKey.KeyID must be the key's resolved
// keyid. w may be nil, which leaves every caller "unknown".
func New(cfg config.Config, r Robots, s Signer, w Whois) *Server {
	return &Server{cfg: cfg, robots: r, signer: s, whois: w}
}

// Process answers the messages of one ext_proc stream, which carries one
// HTTP request.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var resp *extprocv3.ProcessingResponse
		switch r := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = s.requestHeaders(stream.Context(), req, r.RequestHeaders)
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{},
				},
			}
		case *extprocv3.ProcessingRequest_RequestBody:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestBody{
					RequestBody: &extprocv3.BodyResponse{},
				},
			}
		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{},
				},
			}
		case *extprocv3.ProcessingRequest_RequestTrailers:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extprocv3.TrailersResponse{},
				},
			}
		case *extprocv3.ProcessingRequest_ResponseTrailers:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extprocv3.TrailersResponse{},
				},
			}
		default:
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// incoming is what crawl-signer reads from the request headers Envoy sends.
type incoming struct {
	method, authority, path string
	schemes                 []string
	// headers are the regular headers, without pseudo-headers, with
	// lowercase names.
	headers []rules.Header
}

func parseHeaders(h *extprocv3.HttpHeaders) incoming {
	var r incoming

	for _, hv := range h.GetHeaders().GetHeaders() {
		name := strings.ToLower(hv.GetKey())

		value := hv.GetValue()
		if hv.GetRawValue() != nil {
			value = string(hv.GetRawValue())
		}

		switch name {
		case ":method":
			r.method = value
		case ":authority":
			r.authority = value
		case ":path":
			r.path = value
		case schemeHeader:
			r.schemes = append(r.schemes, value)
		}

		if !strings.HasPrefix(name, ":") {
			r.headers = append(r.headers, rules.Header{Name: name, Value: value})
		}
	}

	return r
}

func (s *Server) requestHeaders(
	ctx context.Context,
	req *extprocv3.ProcessingRequest,
	h *extprocv3.HttpHeaders,
) *extprocv3.ProcessingResponse {
	md := map[string]any{"keyid": s.cfg.SigningKey.KeyID}

	internal, addr := source(req.GetAttributes())
	s.caller(ctx, md, internal, addr)

	r := parseHeaders(h)

	// Callers send absolute-form http:// URLs; the gateway speaks https
	// upstream unless asked otherwise.
	scheme := schemeHTTPS
	if len(r.schemes) > 0 {
		if len(r.schemes) != 1 || !strings.EqualFold(r.schemes[0], schemeHTTP) {
			return s.refuse(md, http.StatusForbidden, "scheme")
		}

		scheme = schemeHTTP
	}

	v := rules.Check(rules.Request{
		Method:    r.method,
		Scheme:    scheme,
		Authority: r.authority,
		Path:      r.path,
		Headers:   r.headers,
	})
	if !v.OK {
		return s.refuse(md, v.Status, v.Reason)
	}

	canon := sign.CanonicalAuthority(scheme, r.authority)
	if canon == "" {
		return s.refuse(md, http.StatusForbidden, "target")
	}

	if reason := s.robotsVerdict(
		ctx,
		md,
		internal,
		robots.Origin{Scheme: scheme, Authority: canon},
		r.path,
	); reason != "" {
		return s.refuse(md, http.StatusForbidden, reason)
	}

	sigAuthority := sign.SignatureAuthority(scheme, r.authority)
	if sigAuthority == "" {
		return s.refuse(md, http.StatusForbidden, "target")
	}

	sig, err := s.signer.Headers(ctx, sigAuthority)
	if err != nil || len(sig) == 0 {
		return s.refuse(md, http.StatusServiceUnavailable, "signing")
	}

	md["verdict"] = "ok"
	s.count("ok")

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: &extprocv3.CommonResponse{
					Status:         extprocv3.CommonResponse_CONTINUE,
					HeaderMutation: s.mutation(scheme, sig, r.headers),
					// Envoy picks the upstream cluster by x-crawl-upstream.
					ClearRouteCache: true,
				},
			},
		},
		DynamicMetadata: metadata(md),
	}
}

// caller names the caller in md: "internal" for crawl-signer's own fetches,
// the tailnet node when whois knows it, "unknown" otherwise.
func (s *Server) caller(ctx context.Context, md map[string]any, internal bool, addr netip.Addr) {
	md["caller"], md["caller_tags"] = "unknown", []any{}

	switch {
	case internal:
		md["caller"] = "internal"
	case addr.IsValid() && s.whois != nil:
		c, err := s.whois.Lookup(ctx, addr)
		if err != nil {
			return
		}

		tags := make([]any, len(c.Tags))
		for i, t := range c.Tags {
			tags[i] = t
		}

		md["caller"], md["caller_tags"] = c.Node, tags
	}
}

// robotsVerdict records robots.txt's outcome in md and returns the refusal
// reason, or "" if the request may go ahead.
func (s *Server) robotsVerdict(
	ctx context.Context,
	md map[string]any,
	internal bool,
	o robots.Origin,
	path string,
) string {
	if internal {
		// crawl-signer's own robots.txt fetches, redirects included: checking
		// robots.txt here would wait on the very fetch that is in flight.
		md["robots"] = "skipped"

		return ""
	}

	outcome := s.robots.Check(ctx, o, path)
	md["robots"] = outcome.String()

	switch outcome {
	case robots.Allowed:
		return ""
	case robots.Disallowed:
		return "robots"
	default:
		return "robots-unavailable"
	}
}

// mutation sets the gateway's headers and the signature, and removes every
// header the allowlist does not keep.
func (s *Server) mutation(scheme string, sig, headers []rules.Header) *extprocv3.HeaderMutation {
	set := []rules.Header{{Name: "user-agent", Value: s.cfg.UserAgent}}
	if s.cfg.From != "" {
		set = append(set, rules.Header{Name: "from", Value: s.cfg.From})
	}

	set = append(set, sig...)
	if scheme == schemeHTTP {
		set = append(set, rules.Header{Name: upstreamHeader, Value: schemeHTTP})
	}

	mut := &extprocv3.HeaderMutation{}
	setNames := map[string]bool{}

	for _, x := range set {
		name := strings.ToLower(x.Name)
		setNames[name] = true
		mut.SetHeaders = append(mut.SetHeaders, header(name, x.Value))
	}

	// Envoy ignores removal of host; overwritten headers are left out so
	// the result does not depend on whether Envoy removes or sets first.
	// Without x-forwarded-proto Envoy matches no route after the route cache
	// is cleared; the route config strips it before the request leaves.
	_, drop := rules.Allowlist(headers)
	seen := map[string]bool{}

	for _, name := range drop {
		if name == "host" || name == "x-forwarded-proto" || setNames[name] || seen[name] {
			continue
		}

		seen[name] = true
		mut.RemoveHeaders = append(mut.RemoveHeaders, name)
	}

	return mut
}

// source reports whether the request came in on Envoy's internal listener,
// which carries the listener metadata crawl.internal = true, and the caller
// address for whois. Anything else, including missing attributes, is a
// normal caller, so robots.txt can only be skipped by Envoy's own config.
func source(attrs map[string]*structpb.Struct) (bool, netip.Addr) {
	var (
		internal bool
		addr     netip.Addr
	)

	for _, st := range attrs {
		f := st.GetFields()
		lm := f["xds.listener_metadata"].GetStructValue().GetFields()
		// Envoy's struct conversion may use the proto or the JSON field name.
		for _, key := range []string{"filter_metadata", "filterMetadata"} {
			crawl := lm[key].GetStructValue().GetFields()[namespace].GetStructValue().GetFields()
			v, ok := crawl["internal"].GetKind().(*structpb.Value_BoolValue)
			if ok && v.BoolValue {
				internal = true
			}
		}
		if s := f["source.address"].GetStringValue(); s != "" {
			if ap, err := netip.ParseAddrPort(s); err == nil {
				addr = ap.Addr().Unmap()
			} else if a, err := netip.ParseAddr(s); err == nil {
				addr = a.Unmap()
			}
		}
	}
	return internal, addr
}

func (s *Server) refuse(
	md map[string]any,
	status int,
	reason string,
) *extprocv3.ProcessingResponse {
	md["verdict"] = reason
	s.count(reason)
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				//nolint:gosec // G115: status is one of net/http's constants.
				Status: &typev3.HttpStatus{Code: typev3.StatusCode(status)},
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{header(refusalHeader, reason)},
				},
				Details: "crawl_gateway_" + reason,
			},
		},
		DynamicMetadata: metadata(md),
	}
}

func (s *Server) count(verdict string) {
	if s.Count != nil {
		s.Count(verdict)
	}
}

func header(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: name, RawValue: []byte(value)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func metadata(md map[string]any) *structpb.Struct {
	ns, err := structpb.NewStruct(md)
	if err != nil {
		panic(err) // only strings, ints and string lists go in
	}
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{namespace: structpb.NewStructValue(ns)},
	}
}
