# Getting started

By the end of this page, a request you send through Envoy reaches a site with your bot's `User-Agent` and a
Web Bot Auth signature, and a request robots.txt disallows is refused.

You need a Linux host (amd64 or arm64) with Docker, `curl`, `jq` and `openssl`, and access to the internet. Envoy runs
in a container; crawl-signer runs as a process. The example bot is `ExampleBot`.

## 1. Download crawl-signer

Download the binary and `SHA256SUMS` from the [latest release](https://github.com/matchory/crawl-signer/releases),
and check them:

```bash
version=0.2.0
arch=$(dpkg --print-architecture 2>/dev/null || echo amd64)
curl -sSLO "https://github.com/matchory/crawl-signer/releases/download/v${version}/crawl-signer_${version}_linux_${arch}"
curl -sSLO "https://github.com/matchory/crawl-signer/releases/download/v${version}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
install -m 0755 "crawl-signer_${version}_linux_${arch}" ./crawl-signer
```

`sha256sum` prints `OK`. [Verify a release](guides/verify-a-release.md) also checks where the binary was built.

## 2. Create a signing key

```bash
openssl genpkey -algorithm ed25519 -out key.pem
```

This is the key that identifies your bot. For a real deployment, [Choose a signing key](guides/choose-a-signing-key.md)
compares this with keeping the key in OpenBao or Vault.

## 3. Configure crawl-signer

The example Envoy configuration expects the two sockets under `/run`:

```bash
sudo mkdir -p /run/envoy /run/crawl-signer
sudo chown "$(id -u):$(id -g)" /run/envoy /run/crawl-signer
```

Save this as `config.json`:

```json
{
  "listen": "/run/crawl-signer/grpc.sock",
  "envoy_socket": "/run/envoy/internal.sock",
  "user_agent": "Mozilla/5.0 (compatible; ExampleBot/1.0; +https://bot.example.com)",
  "signature_agent": "https://bot.example.com",
  "robots_agent": "ExampleBot",
  "robots_cache_bytes": 16777216,
  "signing_key": { "private_key": { "filename": "key.pem" } }
}
```

[Configuration](reference/config.md) describes every field.

## 4. Start Envoy and crawl-signer

Get the example configuration and start Envoy with it, as your own user so it can share the sockets:

```bash
curl -sSLO https://raw.githubusercontent.com/matchory/crawl-signer/main/examples/envoy.yaml
docker run -d --name crawl-envoy --network host \
  -e ENVOY_UID="$(id -u)" -e ENVOY_GID="$(id -g)" \
  -v "$PWD/envoy.yaml:/etc/envoy/envoy.yaml:ro" -v /run/envoy:/run/envoy -v /run/crawl-signer:/run/crawl-signer \
  envoyproxy/envoy:v1.40.2 -c /etc/envoy/envoy.yaml
```

Then start crawl-signer in a second terminal:

```bash
./crawl-signer -config config.json
```

It prints the `keyid` it signs with:

```text
crawl-signer v0.2.0 listening on /run/crawl-signer/grpc.sock, signing with keyid qxN8…
```

## 5. Send a request

httpbin.org answers with the headers it received. Send it a request through the gateway, with a cookie and a
`User-Agent` of your own:

```bash
curl -sS --proxy http://127.0.0.1:3128 -A curl -H 'Cookie: session=secret' http://httpbin.org/headers | jq .headers
```

```json
{
  "Accept": "*/*",
  "Host": "httpbin.org",
  "Signature": "sig1=:mJ0w…:",
  "Signature-Agent": "\"https://bot.example.com\"",
  "Signature-Input": "sig1=(\"@authority\" \"signature-agent\");created=…;keyid=\"qxN8…\";…;tag=\"web-bot-auth\"",
  "User-Agent": "Mozilla/5.0 (compatible; ExampleBot/1.0; +https://bot.example.com)"
}
```

The request went out over https, although you sent `http://`. Your `User-Agent` and cookie are gone, and `Accept`,
which is on the allowlist, stayed. The gateway's `User-Agent` and a signature for `httpbin.org` are there. Headers
that httpbin's own load balancer adds, such as `X-Amzn-Trace-Id`, appear too.

## 6. Send a request robots.txt disallows

httpbin.org's robots.txt disallows `/deny` for every bot:

```bash
curl -sS -D - -o /dev/null --proxy http://127.0.0.1:3128 http://httpbin.org/deny
```

```text
HTTP/1.1 403 Forbidden
x-crawl-gateway-refusal: robots
```

The request never reached httpbin.org. Envoy's log shows both requests and their verdicts:

```bash
docker logs crawl-envoy 2>&1 | grep verdict | jq -c '{path, verdict, robots, response_code}'
```

## Clean up

Stop crawl-signer with Ctrl-C, then:

```bash
docker rm -f crawl-envoy
```

## Next

- [Deploy with Envoy](guides/deploy-with-envoy.md) to run the gateway as services, restrict what it can reach and let
  callers on other hosts in.
- [Become a verified bot](guides/become-a-verified-bot.md) to publish your key so sites can check the signature.
- [How a request flows](explanation/how-a-request-flows.md) for what happened in step 5.
