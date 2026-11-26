# Become a verified bot

Sites that check Web Bot Auth signatures need your public key. You publish it in a key directory under your
[`signature_agent`](../reference/config.md#signature_agent) URL, then register that URL with each verifier. After
that, a verifier such as Cloudflare recognises every request from your gateway as your bot, whatever address it
comes from.

You need the gateway running ([Deploy with Envoy](deploy-with-envoy.md)), an HTTPS site at your `signature_agent`
URL, such as `https://bot.example.com`, and your signing key's public part and `keyid`
([Choose a signing key](choose-a-signing-key.md)).

## Publish the key directory

The directory is a JSON Web Key Set at `/.well-known/http-message-signatures-directory` on the `signature_agent`
origin, served over HTTPS:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  ]
}
```

`x` is the raw 32-byte public key, base64url-encoded without padding. Never include `d`, the private part.
[Choose a signing key](choose-a-signing-key.md#a-transit-key) shows how to get `x` from a file or from Transit; for
a file:

```bash
openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

Cloudflare also requires the directory's response to prove you hold each key it lists
([Cloudflare's requirements](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)):

- the content type `application/http-message-signatures-directory+json`;
- a `Content-Digest` header with the body's SHA-256;
- for each key, a signature in `Signature` and `Signature-Input` that covers `"@authority";req` and
  `"content-digest"`, with `keyid` set to the key's thumbprint, `alg="ed25519"`, `created`, `expires` and
  `tag="http-message-signatures-directory"`.

crawl-signer doesn't serve or sign the directory: your site at the `signature_agent` URL does. Cloudflare's
[`web-bot-auth` repository](https://github.com/cloudflare/web-bot-auth) has a signing library and an example that
serves a signed directory from a Cloudflare Worker. With a Transit key, the directory's signatures come from Transit
too: `bao write transit/sign/web-bot-auth input=<base64 signature base>`, with a policy that allows it to whatever
produces the directory.

Check the result with Cloudflare's validator, [`http-signature-directory`](https://crates.io/crates/http-signature-directory):

```bash
cargo install http-signature-directory
http-signature-directory https://bot.example.com
```

It reports each key and whether its proof verifies.

## Register with Cloudflare

In the Cloudflare dashboard, under **Manage Account** > **Configurations** > **Bot Submission Form**, choose the
verification method **Request Signature**, and give your key directory's URL and the `User-Agent` your gateway sends.
The submission's status is under **BotBase** > **Submission history**.

Cloudflare verifies only the structured-string form of `Signature-Agent`, crawl-signer's default:
[`signature_agent_form`](../reference/config.md#signature_agent_form) must be `string`.

Cloudflare's verified bot policy also asks that the addresses a bot sends from are used by nothing else. Send from
addresses only the gateway uses: [Deploy with Envoy](deploy-with-envoy.md#3-restrict-what-envoy-can-reach).

## Check it works

Two things must agree: the key in your directory, and the key crawl-signer signs with.

```bash
http-signature-directory https://bot.example.com
journalctl -u crawl-signer -o cat | grep keyid
```

The validator must report a valid proof for every key. The `keyid` crawl-signer logs at startup must be the
thumbprint of one of them, computed as [Choose a signing key](choose-a-signing-key.md#a-transit-key) shows. Every
request the gateway sends names that `keyid` in its `Signature-Input`.
