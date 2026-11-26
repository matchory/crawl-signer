# Configuration

crawl-signer reads one JSON file, named by `-config`, at startup:

```bash
crawl-signer -config /etc/crawl-signer/config.json
```

It refuses to start when a required field is missing, a value is invalid or the file has a field it doesn't know,
and prints which. A change takes effect at the next start. Secrets are read once, at startup, too.

```json
{
  "listen": "/run/crawl-signer/grpc.sock",
  "envoy_socket": "/run/envoy/internal.sock",
  "metrics_listen": "127.0.0.1:9100",
  "directory_listen": "127.0.0.1:9200",
  "user_agent": "Mozilla/5.0 (compatible; ExampleBot/1.0; +https://bot.example.com)",
  "from": "bot@example.com",
  "signature_agent": "https://bot.example.com",
  "signature_agent_form": "string",
  "robots_agent": "ExampleBot",
  "robots_cache_bytes": 67108864,
  "max_crawl_delay_seconds": 60,
  "tailscale_whois": false,
  "signing_key": { "private_key": { "filename": "/run/credentials/crawl-signer.service/key.pem" } }
}
```

## `listen`

| Type | Default |
| --- | --- |
| path | required |

The Unix socket Envoy's `ext_proc` filter connects to. crawl-signer removes a file at this path, creates the socket
and gives it mode `0660`, so a process in its group can connect. Point Envoy's `crawl_signer` cluster at it.

## `envoy_socket`

| Type | Default |
| --- | --- |
| path | required |

The Unix socket of Envoy's internal listener. crawl-signer fetches robots.txt through it, so a fetch leaves the way a
crawl does. See [Envoy interface](envoy-interface.md#the-internal-listener).

## `metrics_listen`

| Type | Default |
| --- | --- |
| TCP address | none |

Where crawl-signer serves Prometheus metrics at `/metrics`, such as `127.0.0.1:9100`. Without it, there is no metrics
endpoint. [Metrics](metrics.md) lists them.

## `directory_listen`

| Type | Default |
| --- | --- |
| TCP address | none |

Where crawl-signer serves your signed key directory at `/.well-known/http-message-signatures-directory`, such as
`127.0.0.1:9200`. Your site at [`signature_agent`](#signature_agent) forwards that path here. Without it, crawl-signer
serves no directory. [Become a verified bot](../guides/become-a-verified-bot.md#publish-the-key-directory) sets it up.

## `user_agent`

| Type | Default |
| --- | --- |
| string | required |

The `User-Agent` of every request that leaves. It must contain [`robots_agent`](#robots_agent).

## `from`

| Type | Default |
| --- | --- |
| string | none |

The `From` header of every request that leaves: an address site operators can write to. Without it, requests leave
without `From`.

## `signature_agent`

| Type | Default |
| --- | --- |
| `https://` URL | required |

The `Signature-Agent`: the origin under which you publish your
[key directory](../guides/become-a-verified-bot.md#publish-the-key-directory), such as `https://bot.example.com`. It
may contain only printable ASCII other than `"` and `\`, since it is sent inside a quoted string.

## `signature_agent_form`

| Type | Default |
| --- | --- |
| `"string"` or `"dictionary"` | `"string"` |

How `Signature-Agent` is sent and covered by the signature.

| Form | `Signature-Agent` | Covered component |
| --- | --- | --- |
| `string` | `"https://bot.example.com"` | `"signature-agent"` |
| `dictionary` | `sig1="https://bot.example.com"` | `"signature-agent";key="sig1"` |

The two forms come from different revisions of the Web Bot Auth drafts. [Signatures](../explanation/signatures.md#the-signature-agent-form)
explains which verifier accepts which.

## `robots_agent`

| Type | Default |
| --- | --- |
| product token | required |

The name robots.txt groups are matched against, such as `ExampleBot`. It may contain only letters, `_` and `-`
(RFC 9309, section 2.2.1), and it must appear in `user_agent`, compared without case, so site operators can tell
from their logs which group applies.

## `robots_cache_bytes`

| Type | Default |
| --- | --- |
| integer, bytes | required |

How much memory the parsed robots.txt rules may take. Past it, the least recently used origins are dropped and
fetched again when next needed. The size is an estimate: each origin counts 64 bytes, plus 32 bytes and the
pattern's length for each rule. 64 MiB holds tens of thousands of typical origins.

## `max_crawl_delay_seconds`

| Type | Default |
| --- | --- |
| integer, seconds | `60` |

The longest `Crawl-delay` crawl-signer applies. A robots.txt asking for more gets this; `0` means the default. A site
with `Crawl-delay: 86400` would otherwise allow one request a day.
[robots.txt](../explanation/robots-txt.md#crawl-delay) explains the pacing.

## `tailscale_whois`

| Type | Default |
| --- | --- |
| boolean | `false` |

With `true`, crawl-signer asks the local `tailscaled` which [Tailscale](https://tailscale.com) node sent each
request, and records the node's name and tags in the [dynamic metadata](envoy-interface.md#dynamic-metadata).
Answers are cached for 10 minutes, failures for 5 seconds, and a lookup waits at most 2 seconds. A failed lookup
records the caller as `unknown` and doesn't refuse the request. Without it, every caller is `unknown`.

## `signing_key`

The Ed25519 key that signs requests: exactly one of `private_key` and `transit`.
[Choose a signing key](../guides/choose-a-signing-key.md) compares them.

### `signing_key.keyid`

| Type | Default |
| --- | --- |
| string | the key's thumbprint; required with `transit` |

The `keyid` of each signature: the key's [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint, as Web
Bot Auth requires. For a private key crawl-signer computes it. For a Transit key you must set it, and crawl-signer
reads the key's public part at startup to check it. Either way, crawl-signer refuses to start if the `keyid` isn't the
key's thumbprint.

### `signing_key.private_key`

| Type | Default |
| --- | --- |
| [data source](#data-sources) | none |

The private key, in one of two formats:

- PEM-encoded PKCS #8, as `openssl genpkey -algorithm ed25519` writes it;
- a JWK with `"kty": "OKP"`, `"crv": "Ed25519"` and the private part `d`. If it has `x` too, `x` must be the public
  key of `d`.

### `signing_key.transit`

An [OpenBao](https://openbao.org) or Vault [Transit](https://openbao.org/docs/secrets/transit/) key of type
`ed25519`. crawl-signer posts what it needs signed to `<address>/v1/<mount>/sign/<key>` and never sees the private
key. A sign call times out after 2 seconds.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `address` | `unix:///path` or `http(s)://host:port` | required | A local proxy's socket, or the server |
| `mount` | string | `transit` | The Transit mount's path |
| `key` | string | required | The key's name |
| `version` | integer ≥ 1 | required | The key version to sign with, so a rotation takes effect only when you change it |
| `token` | [data source](#data-sources) | none | The token, sent as `X-Vault-Token`. Leave it out behind a proxy that adds the token, such as OpenBao Proxy or Vault Agent with `use_auto_auth_token` |

Leading and trailing whitespace is removed from the token. For `https` addresses, crawl-signer trusts the system's CA
certificates; set `SSL_CERT_FILE` in its environment to trust another.

## Data sources

A secret's location, in the shape of Envoy's
[`DataSource`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto#config-core-v3-datasource):
exactly one of these fields.

| Field | Reads |
| --- | --- |
| `filename` | the file's content |
| `environment_variable` | the variable's value; a variable that is unset or empty is an error |
| `inline_string` | the string itself |
