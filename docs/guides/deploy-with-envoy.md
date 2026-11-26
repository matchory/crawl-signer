# Deploy with Envoy

At the end, Envoy and crawl-signer run as systemd services on a Linux host, each as its own user. Envoy can reach
only public addresses, and callers on other hosts can use the gateway without making it an open proxy.

You need a Linux host with systemd and nftables, Envoy 1.39 or newer, crawl-signer from a
[verified release](verify-a-release.md), and a signing key: see [Choose a signing key](choose-a-signing-key.md).
[Getting started](../getting-started.md) runs the same parts by hand, if you'd like to try them first.

## 1. Run each as its own user

crawl-signer parses robots.txt files from anywhere and can ask for signatures, so it runs as an unprivileged user
that can do nothing else. Envoy and crawl-signer connect to each other's Unix sockets, so each socket's directory
belongs to the other's group:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin crawl-signer
useradd --system --no-create-home --shell /usr/sbin/nologin envoy
install -o root -g root -m 0755 crawl-signer_0.2.0_linux_amd64 /usr/local/bin/crawl-signer
```

`/etc/systemd/system/crawl-signer.service`:

```ini
[Unit]
Description=crawl-signer
After=network-online.target
Wants=network-online.target

[Service]
User=crawl-signer
Group=crawl-signer
# /run/crawl-signer is setgid and belongs to Envoy's group, so the socket
# crawl-signer creates in it does too.
RuntimeDirectory=crawl-signer
RuntimeDirectoryMode=2750
ExecStartPre=+/usr/bin/chgrp envoy /run/crawl-signer
LoadCredential=key.pem:/etc/crawl-signer/key.pem
ExecStart=/usr/local/bin/crawl-signer -config /etc/crawl-signer/config.json
Restart=always
RestartSec=1s
UMask=0007
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

With `LoadCredential`, systemd hands the key to the service at `/run/credentials/crawl-signer.service/key.pem`, and
the file in `/etc` can stay readable by root alone. Point [`private_key`](../reference/config.md#signing_keyprivate_key)
at that path.

Envoy's unit mirrors it: `User=envoy`, `Group=envoy`, `RuntimeDirectory=envoy`, `RuntimeDirectoryMode=2750` and
`ExecStartPre=+/usr/bin/chgrp crawl-signer /run/envoy`, so the internal listener's socket belongs to crawl-signer's
group. Envoy creates it with mode `0660` (`mode: 432` in the example).

## 2. Start from the example configuration

Copy [`examples/envoy.yaml`](../../examples/envoy.yaml) to `/etc/envoy/envoy.yaml`. When you change it, keep these
parts, which the [security model](../../SECURITY.md#environment-properties) relies on (E1):

- the `ext_proc` filter, first, with `failure_mode_allow: false` and the processing mode, attributes and timeouts the
  [Envoy interface](../reference/envoy-interface.md#what-envoy-must-send) lists;
- the early header mutation that removes `x-crawl-upstream`, and the routes that choose the cluster by it and remove
  it, `x-forwarded-proto` and Envoy's own headers;
- the `crawl.internal` metadata on the internal listener, and on no other;
- an access log with the `crawl` metadata, to know who sent what.

Check a changed file before Envoy loads it:

```bash
envoy --mode validate -c /etc/envoy/envoy.yaml
```

## 3. Restrict what Envoy can reach

crawl-signer refuses internal addresses written in a URL, but a public name can resolve to an internal address. The
host's firewall must stop Envoy from connecting to them (E3). This nftables table, loaded on its own so it leaves other
rules alone, lets Envoy's user connect only to public addresses on ports 80 and 443:

```text
table inet crawl_gateway {
  set internal4 {
    type ipv4_addr; flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
                 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }
  }
  set internal6 {
    type ipv6_addr; flags interval
    elements = { ::/96, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/32, 2002::/16,
                 fc00::/7, fe80::/10, fec0::/10, ff00::/8 }
  }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid "envoy" oifname "lo" accept
    meta skuid "envoy" ip daddr @internal4 counter reject
    meta skuid "envoy" ip6 daddr @internal6 counter reject
    meta skuid "envoy" udp dport 53 accept
    meta skuid "envoy" tcp dport { 80, 443 } accept
    meta skuid "envoy" counter drop
  }
}
```

DNS goes to the resolver in `/etc/resolv.conf`; if that is on a private address, add an `accept` for it before the
`reject` rules.

To send from addresses only the gateway uses, add them to the host, give both forward proxy clusters an
[`upstream_bind_config`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-field-config-cluster-v3-cluster-upstream-bind-config)
with those addresses, and drop anything else sent from them:

```text
    ip saddr 192.0.2.10 meta skuid != "envoy" counter drop
```

## 4. Let callers on other hosts in

The example listens on `127.0.0.1:3128` only. Listening on another address makes the gateway an open proxy for
whoever can reach it, under your bot's name. Pick one way to let only your crawlers in (E5):

- **Network policy.** Listen on a private interface and add Envoy's
  [network RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/rbac_filter)
  before the HTTP connection manager, allowing only your crawlers' source ranges:

  ```yaml
  - name: envoy.filters.network.rbac
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC
      stat_prefix: callers_rbac
      rules:
        action: ALLOW
        policies:
          crawlers:
            permissions: [{ any: true }]
            principals:
            - remote_ip: { address_prefix: 10.20.0.0, prefix_len: 16 }
  ```

- **A tailnet.** Keep the loopback listener, publish it with `tailscale serve --proxy-protocol=2`, add Envoy's
  `proxy_protocol` listener filter so the caller's tailnet address is the downstream address, and turn on
  [`tailscale_whois`](../reference/config.md#tailscale_whois) to record each caller's node and tags. Restrict who
  can reach the service in the tailnet policy.
- **Client certificates.** Terminate TLS on the listener and require certificates from your own CA.

## 5. Check it works

```bash
systemctl enable --now crawl-signer envoy
curl -sS -o /dev/null -w '%{http_code}\n' --proxy http://127.0.0.1:3128 http://example.com/
curl -sS -D - -o /dev/null --proxy http://127.0.0.1:3128 -X POST http://example.com/ | grep -i x-crawl-gateway-refusal
journalctl -u envoy -n 2 -o cat
```

The first prints the origin's status, `200`. The second prints `x-crawl-gateway-refusal: method`. Envoy's access
log shows both, with `"verdict":"ok"` and `"verdict":"method"`. From the gateway host, a request Envoy sends to an
internal address now fails at the firewall:

```bash
sudo -u envoy curl -sS --max-time 3 http://10.0.0.1/ ; echo $?
```

prints a refused connection and a non-zero exit status.

## Next

- [Become a verified bot](become-a-verified-bot.md) to publish your key and register it.
- [Metrics](../reference/metrics.md) to monitor verdicts, robots.txt fetches and the signing key.
