# Snell v6 support

This fork of [chen08209/Clash.Meta](https://github.com/chen08209/Clash.Meta) (branch `FlClash`, itself derived from
[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)) adds Snell v6 to the `snell` outbound and inbound.

Outbound example:

```yaml
proxies:
  - name: snell-v6
    type: snell
    server: example.com
    port: 443
    psk: your-psk
    version: 6
    mode: default   # default | unshaped | unsafe-raw
    udp: true
```

- `default`: shaped and obfuscated, `unshaped`: plain AES, `unsafe-raw`: plaintext with no PSK check.
- v6 relays UDP natively over the TCP connection. QUIC is not a Snell mode; it works as UDP traffic over the relay.
- v6 does not support `obfs-opts` or connection reuse.

Licensed under GPL-3.0, same as upstream.
