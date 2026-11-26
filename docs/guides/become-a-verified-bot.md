# Become a verified bot

Sites that check Web Bot Auth signatures need your public key. You publish it in a key directory under your
[`signature_agent`](../reference/config.md#signature_agent) URL, then register that URL with each verifier. After
that, a verifier such as Cloudflare recognises every request from your gateway as your bot, whatever address it
comes from.

You need the gateway running ([Deploy with Envoy](deploy-with-envoy.md)) and an HTTPS site at your
`signature_agent` URL, such as `https://bot.example.com`, that can forward one path to crawl-signer.

## Publish the key directory

The directory is a JSON Web Key Set at `/.well-known/http-message-signatures-directory` on the `signature_agent`
origin, served over HTTPS. Cloudflare also requires the response to prove you hold each key it lists, with a
signature that expires
([Cloudflare's requirements](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)), so
the directory can't be a static file. crawl-signer serves it, signed with the key it signs requests with.

1. Set [`directory_listen`](../reference/config.md#directory_listen) and restart crawl-signer:

   ```json
   "directory_listen": "127.0.0.1:9200"
   ```

   With a Transit key, the policy also needs `read` on the key:
   [Choose a signing key](choose-a-signing-key.md#a-transit-key).

2. Forward the path from your site to it. With Caddy:

   ```text
   bot.example.com {
     reverse_proxy /.well-known/http-message-signatures-directory 127.0.0.1:9200
   }
   ```

   With nginx:

   ```nginx
   location = /.well-known/http-message-signatures-directory {
     proxy_pass http://127.0.0.1:9200;
   }
   ```

   If your site runs on another host, listen on an address that host can reach, and let only it in. The directory is
   public, but each request to the listener is answered by crawl-signer.

The signature covers your `signature_agent` authority, whichever `Host` your site forwards, and is valid for an hour.
crawl-signer signs a new one 10 minutes before the old one expires, and sends `Cache-Control: max-age=300`, so a
cached copy is still valid when it's used. If crawl-signer can't sign, it answers `503`: an unsigned directory fails
verification anyway.

Check the result with Cloudflare's validator, [`http-signature-directory`](https://crates.io/crates/http-signature-directory):

```bash
cargo install http-signature-directory
http-signature-directory https://bot.example.com
```

It reports each key and whether its proof verifies.

### Serve it yourself

To list more than one key, as during a [rotation](choose-a-signing-key.md#rotate-the-key), serve the directory from
your site. The body is:

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

`x` is the raw 32-byte public key, base64url-encoded without padding. Never include `d`, the private part. The
response needs:

- the content type `application/http-message-signatures-directory+json`;
- a `Content-Digest` header with the body's SHA-256;
- for each key, a signature in `Signature` and `Signature-Input` that covers `"@authority";req` and
  `"content-digest"`, with `keyid` set to the key's thumbprint, `alg="ed25519"`, `created`, `expires` and
  `tag="http-message-signatures-directory"`.

Cloudflare's [`web-bot-auth` repository](https://github.com/cloudflare/web-bot-auth) has a signing library and an
example that serves a signed directory from a Cloudflare Worker.

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
