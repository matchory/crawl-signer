# Envoy interface

crawl-signer is an Envoy [`ext_proc`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
server. This page lists what it expects from Envoy and what it answers. [`examples/envoy.yaml`](../../examples/envoy.yaml)
is a configuration that meets every requirement; the end-to-end test runs it unchanged.

## What Envoy must send

| Setting | Value | Why |
| --- | --- | --- |
| `processing_mode.request_header_mode` | `SEND` | The verdict is made on the request headers |
| other `processing_mode` fields | `SKIP` or `NONE` | crawl-signer answers other phases with "continue", so sending them only costs time |
| `request_attributes` | `source.address`, `xds.listener_metadata` | The caller's address, for [`tailscale_whois`](config.md#tailscale_whois), and the [internal listener's](#the-internal-listener) mark |
| `failure_mode_allow` | `false` | Without it, a request crawl-signer doesn't answer leaves unchecked and unsigned |
| `metadata_options.receiving_namespaces.untyped` | `[crawl]` | Lets the [dynamic metadata](#dynamic-metadata) reach the access log |
| `message_timeout` | at least `13s` | crawl-signer can wait 10 seconds for robots.txt and 2 for a signature |
| `mutation_rules.allow_envoy` | `true` | crawl-signer removes `x-envoy-*` headers a caller sends |

The filter must come before the dynamic forward proxy and the router, and the gRPC cluster must use HTTP/2.

## Request headers crawl-signer reads

| Header | Meaning |
| --- | --- |
| `:method`, `:authority`, `:path` | The request. A caller sends an absolute-form `http://` URL; `:authority` is its host and port |
| `X-Crawl-Scheme` | `http` to fetch over plain http. Absent, the request goes out over https. Any other value, or the header twice, is refused |
| `Transfer-Encoding`, `Content-Length` | A request body is refused |

## What crawl-signer answers

### A request it lets through

The request continues, with these changes:

| Header | Change |
| --- | --- |
| `User-Agent` | set to [`user_agent`](config.md#user_agent) |
| `From` | set to [`from`](config.md#from), if configured |
| `Signature-Agent`, `Signature-Input`, `Signature` | set to a signature for the request's authority |
| `X-Crawl-Upstream` | set to `http` for a plain-http request; Envoy's route chooses the plain cluster by it |
| `Accept`, `Accept-Encoding`, `Accept-Language`, `If-Modified-Since`, `If-None-Match`, `Range` | kept |
| `Host`, `X-Forwarded-Proto` | kept: Envoy ignores a removal of `Host`, and matches no route without `X-Forwarded-Proto` |
| every other header | removed |

crawl-signer clears the route cache, so Envoy chooses the route again with `X-Crawl-Upstream` in place. Envoy's route
must then remove `X-Crawl-Upstream`, `X-Forwarded-Proto` and the headers Envoy adds itself, so the origin doesn't see
them: `request_headers_to_remove` in the example.

### A request it refuses

An immediate response with an empty body, the status below, the header `X-Crawl-Gateway-Refusal: <reason>` and the
response code details `crawl_gateway_<reason>`.

| Reason | Status | When |
| --- | --- | --- |
| `method` | 405 | The method isn't `GET` or `HEAD` |
| `body` | 413 | The request has `Transfer-Encoding`, or `Content-Length` other than `0` |
| `scheme` | 403 | `X-Crawl-Scheme` isn't exactly one `http` |
| `port` | 403 | The port isn't the scheme's default: 443 for https, 80 for http |
| `target` | 403 | The authority is malformed, has user information or an IPv6 zone, or names `localhost` or an internal address |
| `robots` | 403 | robots.txt disallows the path |
| `robots-unavailable` | 403 | robots.txt can't be fetched and no usable copy is cached |
| `signing` | 503 | The signing key gave no signature and none is cached |

The [security model](../../SECURITY.md#g2-only-a-get-or-head-without-a-body-to-a-hostname-or-a-public-address-on-the-schemes-default-port)
lists exactly which addresses count as internal. When crawl-signer itself doesn't answer, Envoy answers `500`
without the refusal header.

## Dynamic metadata

Every answer carries dynamic metadata in the namespace `crawl`, for the access log
(`%DYNAMIC_METADATA(crawl:verdict)%`):

| Key | Value |
| --- | --- |
| `verdict` | `ok`, or the refusal's reason |
| `robots` | `allowed`, `disallowed`, `unavailable` or `skipped`; absent when the request was refused before robots.txt |
| `caller` | `internal` for crawl-signer's own fetches; with [`tailscale_whois`](config.md#tailscale_whois), the node's name; otherwise `unknown` |
| `caller_tags` | the node's Tailscale tags, or an empty list |
| `keyid` | the signing key's `keyid` |

## The internal listener

crawl-signer fetches robots.txt by sending `GET http://<host>/robots.txt` in absolute form to
[`envoy_socket`](config.md#envoy_socket), with `X-Crawl-Scheme: http` for a plain-http origin. Envoy handles it like
any request, so it is signed and leaves from the same addresses. It follows up to 5 redirects itself.

The listener must carry this metadata, and no other listener may:

```yaml
metadata:
  filter_metadata:
    crawl: { internal: true }
```

For such a request, crawl-signer skips the robots.txt check, which would wait on the fetch in progress. It applies
every other rule. Envoy may convert the metadata's key to `filter_metadata` or `filterMetadata`; crawl-signer reads
both.
