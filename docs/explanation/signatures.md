# Signatures

Every request crawl-signer lets through carries a [Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/)
signature: an [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP message signature with an Ed25519 key, which
an origin checks against the public key in your key directory. A `User-Agent` can be copied by anyone; a signature
only by whoever holds the key.

## What is signed

```text
Signature-Agent: "https://bot.example.com"
Signature-Input: sig1=("@authority" "signature-agent");created=1795425000;expires=1795425060;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";tag="web-bot-auth"
Signature: sig1=:<64 bytes, base64>:
```

The signature covers two components, the ones Web Bot Auth requires:

- `@authority`: the host, and the port if it isn't the scheme's default, lowercased. It's the authority Envoy
  forwards, so the origin computes the same value. A trailing dot stays, because Envoy forwards it.
- `signature-agent`: the URL where the origin finds your key directory.

The parameters are `created` and `expires` (Unix seconds), `keyid` (the key's
[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint), `alg="ed25519"` and `tag="web-bot-auth"`.

The path, the query and the method are not covered. A signature says that this bot sent a request to this host
within this minute, not which request.

## The Signature-Agent form

The Web Bot Auth drafts changed how `Signature-Agent` is written:

- draft-meunier-http-message-signatures-directory-03 makes it a structured string, `"https://bot.example.com"`,
  covered as `"signature-agent"`;
- later drafts make it a dictionary, `sig1="https://bot.example.com"`, covered as
  `"signature-agent";key="sig1"`, so one request can name several agents.

Cloudflare's verifier
[implements the first](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) and fails
a request in the dictionary form, or with any `key` parameter. crawl-signer sends the string form unless you set
[`signature_agent_form`](../reference/config.md#signature_agent_form) to `dictionary`. If you register with several
verifiers, check which form each accepts.

## Caching

Signing costs a call to the signing key: nothing for a local key, a round trip to OpenBao or Vault for Transit. So
crawl-signer signs once per authority and time window, and reuses the signature:

- `created` is the current time rounded down to a multiple of 30 seconds, and `expires` is 60 seconds later;
- a cached signature is reused until 10 seconds before it expires, then replaced.

Every request therefore leaves with a signature that is valid for at least 10 more seconds, and has at most 30
seconds of clock difference to absorb. Concurrent requests for the same authority share one call to the key.

When the key can't be reached, crawl-signer reuses the cached signature for as long as it hasn't expired, then
refuses with `signing`. A Transit outage shorter than about 10 seconds goes unnoticed by most authorities.

## The key ID

Web Bot Auth identifies a key by its JWK thumbprint, so the same key always has the same `keyid`, and a verifier can
look it up in your directory. For a private key, crawl-signer computes it at startup and logs it:

```text
crawl-signer v0.2.0 listening on /run/crawl-signer/grpc.sock, signing with keyid poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U
```

crawl-signer can't read a Transit key's public part, so with Transit you compute the thumbprint once and configure
it: [Choose a signing key](../guides/choose-a-signing-key.md#a-transit-key) shows how.

## Two forms of an authority

crawl-signer keeps two forms of each authority:

- the *canonical* form, for its caches: lowercase, internationalised names in their ASCII form, no trailing dot, no
  default port, IPv6 in its shortest form. `Example.COM.`, `example.com:443` and `example.com` share one robots.txt
  entry and one signature;
- the *signature* form, for `@authority`: what Envoy sends upstream, which keeps a trailing dot.

A cached signature is found by the signature form, so `example.com.` and `example.com` get separate signatures, each
valid for what the origin receives.
