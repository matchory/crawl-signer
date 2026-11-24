// Package extproc is the Envoy ext_proc server: one verdict per request, and
// header mutations for the requests it lets through.
package extproc

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"

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
	whoisTimeout   = 2 * time.Second
)

type Robots interface {
	Check(ctx context.Context, o robots.Origin, path string) robots.Outcome
}

type Signer interface {
	Headers(ctx context.Context, authority string) ([]rules.Header, error)
}

type Whois interface {
	Lookup(ctx context.Context, a netip.Addr) (whois.Caller, error)
}

type Server struct {
	extprocv3.UnimplementedExternalProcessorServer

	cfg    config.Config
	robots Robots
	signer Signer
	whois  Whois

	// Count, if set, is called once per request with its verdict.
	Count func(verdict string)
}

func New(cfg config.Config, r Robots, s Signer, w Whois) *Server {
	return &Server{cfg: cfg, robots: r, signer: s, whois: w}
}

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
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{}}}
		case *extprocv3.ProcessingRequest_RequestBody:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{}}}
		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{}}}
		case *extprocv3.ProcessingRequest_RequestTrailers:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}}}
		case *extprocv3.ProcessingRequest_ResponseTrailers:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}}}
		default:
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (s *Server) requestHeaders(ctx context.Context, req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	md := map[string]any{"keyid": s.cfg.KeyID, "key_version": s.cfg.KeyVersion}

	internal, addr := source(req.GetAttributes())
	md["caller"], md["caller_tags"] = "unknown", []any{}
	if internal {
		md["caller"] = "internal"
	} else if addr.IsValid() {
		wctx, cancel := context.WithTimeout(ctx, whoisTimeout)
		c, err := s.whois.Lookup(wctx, addr)
		cancel()
		if err == nil {
			tags := make([]any, len(c.Tags))
			for i, t := range c.Tags {
				tags[i] = t
			}
			md["caller"], md["caller_tags"] = c.Node, tags
		}
	}

	var method, authority, path string
	var schemes []string
	var headers []rules.Header
	for _, hv := range h.GetHeaders().GetHeaders() {
		name := strings.ToLower(hv.GetKey())
		value := hv.GetValue()
		if hv.GetRawValue() != nil {
			value = string(hv.GetRawValue())
		}
		switch name {
		case ":method":
			method = value
		case ":authority":
			authority = value
		case ":path":
			path = value
		case schemeHeader:
			schemes = append(schemes, value)
		}
		if !strings.HasPrefix(name, ":") {
			headers = append(headers, rules.Header{Name: name, Value: value})
		}
	}

	// Callers send absolute-form http:// URLs; the gateway speaks https
	// upstream unless asked otherwise.
	scheme := "https"
	if len(schemes) > 0 {
		if len(schemes) != 1 || !strings.EqualFold(schemes[0], "http") {
			return s.refuse(md, 403, "scheme")
		}
		scheme = "http"
	}

	if v := rules.Check(rules.Request{Method: method, Scheme: scheme, Authority: authority, Path: path, Headers: headers}); !v.OK {
		return s.refuse(md, v.Status, v.Reason)
	}
	canon := sign.CanonicalAuthority(scheme, authority)
	if canon == "" {
		return s.refuse(md, 403, "target")
	}

	if internal {
		// The signer's own robots.txt fetches, redirects included: checking
		// robots here would wait on the very fetch that is in flight.
		md["robots"] = "skipped"
	} else {
		outcome := s.robots.Check(ctx, robots.Origin{Scheme: scheme, Authority: canon}, path)
		md["robots"] = outcome.String()
		switch outcome {
		case robots.Disallowed:
			return s.refuse(md, 403, "robots")
		case robots.Unavailable:
			return s.refuse(md, 403, "robots-unavailable")
		}
	}

	sig, err := s.signer.Headers(ctx, canon)
	if err != nil {
		return s.refuse(md, 503, "signing")
	}

	set := []rules.Header{{Name: "user-agent", Value: s.cfg.UserAgent}}
	if s.cfg.From != "" {
		set = append(set, rules.Header{Name: "from", Value: s.cfg.From})
	}
	set = append(set, sig...)
	if scheme == "http" {
		set = append(set, rules.Header{Name: upstreamHeader, Value: "http"})
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
	_, drop := rules.Allowlist(headers)
	seen := map[string]bool{}
	for _, name := range drop {
		if name == "host" || setNames[name] || seen[name] {
			continue
		}
		seen[name] = true
		mut.RemoveHeaders = append(mut.RemoveHeaders, name)
	}

	md["verdict"] = "ok"
	s.count("ok")
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{
			Response: &extprocv3.CommonResponse{
				Status:         extprocv3.CommonResponse_CONTINUE,
				HeaderMutation: mut,
				// Envoy picks the upstream cluster by x-crawl-upstream.
				ClearRouteCache: true,
			},
		}},
		DynamicMetadata: metadata(md),
	}
}

// source reads source.address from the request attributes. A non-IP address
// means Envoy's internal unix-socket listener; the caller listener always
// carries the tailnet IP from PROXY protocol. A missing attribute is treated
// as an unknown caller, so a misconfigured Envoy cannot skip robots.txt.
func source(attrs map[string]*structpb.Struct) (internal bool, addr netip.Addr) {
	for _, st := range attrs {
		v, ok := st.GetFields()["source.address"]
		if !ok {
			continue
		}
		s := v.GetStringValue()
		if ap, err := netip.ParseAddrPort(s); err == nil {
			return false, ap.Addr().Unmap()
		}
		if a, err := netip.ParseAddr(s); err == nil {
			return false, a.Unmap()
		}
		return true, netip.Addr{}
	}
	return false, netip.Addr{}
}

func (s *Server) refuse(md map[string]any, status int, reason string) *extprocv3.ProcessingResponse {
	md["verdict"] = reason
	s.count(reason)
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extprocv3.ImmediateResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode(status)},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{header(refusalHeader, reason)}},
			Details: "crawl_gateway_" + reason,
		}},
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
	return &structpb.Struct{Fields: map[string]*structpb.Value{namespace: structpb.NewStructValue(ns)}}
}
