# Choose a signing key

crawl-signer signs with an Ed25519 key that lives in one of two places. Whoever can use the key can sign as your
bot from anywhere, so choose by where the key is safest in your setup.

| | A private key | A Transit key |
| --- | --- | --- |
| Where the key is | In crawl-signer's memory | In OpenBao or Vault; crawl-signer only asks for signatures |
| What a compromise of the host gives | The key itself, usable anywhere until you replace it | Signatures, for as long as the attacker keeps the host |
| Cost per signature | None | One HTTP round trip per authority every 30 seconds while it is crawled |
| Runs without | Anything else | A reachable OpenBao or Vault, which holds signing up when it's down |
| `keyid` | Computed | You compute and configure it |

Both are configured under [`signing_key`](../reference/config.md#signing_key).

## A private key

Generate it:

```bash
openssl genpkey -algorithm ed25519 -out key.pem
```

Then deliver it the way your platform delivers secrets. crawl-signer reads it from a
[data source](../reference/config.md#data-sources), as Envoy reads its own secrets:

| Delivered as | Configuration |
| --- | --- |
| A file: systemd `LoadCredential`, a Kubernetes Secret volume, Vault Agent or OpenBao Agent templates, the Secrets Store CSI driver | `{"private_key": {"filename": "/run/credentials/crawl-signer.service/key.pem"}}` |
| An environment variable: a container platform's secret injection, `op run`, `doppler run` | `{"private_key": {"environment_variable": "CRAWL_SIGNER_KEY"}}` |
| Inline in the configuration, for tests | `{"private_key": {"inline_string": "-----BEGIN PRIVATE KEY-----\n..."}}` |

The key may be PEM-encoded PKCS #8, as above, or a JWK with `d`. crawl-signer logs the key's `keyid` when it starts.

Keep the file readable by crawl-signer's user alone. With systemd's `LoadCredential`, keep it readable by root
alone: systemd hands crawl-signer a copy only it can read.

## A Transit key

Create an Ed25519 key, and a policy that can sign with it and do nothing else:

```bash
bao secrets enable transit
bao write -f transit/keys/web-bot-auth type=ed25519
bao policy write crawl-signer - <<'EOF'
path "transit/sign/web-bot-auth" {
  capabilities = ["update"]
}
EOF
```

`vault` takes the same commands. Give crawl-signer a token with this policy in one of two ways:

- **Behind a proxy.** Run [OpenBao Proxy](https://openbao.org/docs/agent-and-proxy/proxy/) or Vault Agent on the same
  host with auto-auth and `api_proxy { use_auto_auth_token = "force" }`, listening on a Unix socket only
  crawl-signer's group can open. crawl-signer then holds no token at all:

  ```json
  "signing_key": {
    "keyid": "<thumbprint>",
    "transit": { "address": "unix:///run/crawl-signer-bao/bao.sock", "key": "web-bot-auth", "version": 1 }
  }
  ```

- **With a token.** Give crawl-signer the token as a data source. It doesn't renew the token, so use a periodic
  token or one that outlives the process, and restart crawl-signer with a new one:

  ```json
  "transit": {
    "address": "https://openbao.example.com:8200", "key": "web-bot-auth", "version": 1,
    "token": { "filename": "/run/credentials/crawl-signer.service/bao-token" }
  }
  ```

crawl-signer can't read the key's public part, so compute its `keyid` once, from the public key Transit reports. The
same commands give the `x` you publish in your [key directory](become-a-verified-bot.md):

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
x=$(bao read -field=keys -format=json transit/keys/web-bot-auth | jq -r '.["1"].public_key' |
  openssl base64 -d -A | b64url)
printf '{"crv":"Ed25519","kty":"OKP","x":"%s"}' "$x" | openssl dgst -sha256 -binary | b64url; echo
```

Replace `"1"` with the key version you sign with.

## Rotate the key

A new key must be in your key directory before crawl-signer signs with it, because verifiers look up each
signature's `keyid` there:

1. Create the new key: a new file, or `bao write -f transit/keys/web-bot-auth/rotate`.
2. Add its public key to your directory, next to the old one, and wait until verifiers have it. Cloudflare asks you
   to contact them for a key rotation.
3. Point crawl-signer at the new key: the new file, or `version` and `keyid` for Transit. Restart it.
4. Once no signature with the old `keyid` is valid, 60 seconds later, remove the old key from the directory.

## Check it works

crawl-signer logs the `keyid` it signs with at startup:

```bash
journalctl -u crawl-signer -n 5 -o cat | grep keyid
```

It must equal the thumbprint of the key in your directory. Every request's `Signature-Input` names it, and
`crawl_signer_sign_total{result="error"}` stays at 0 while signing works.
