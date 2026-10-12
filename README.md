# pypproxy

MITM HTTP/HTTPS proxy for inspecting, modifying, and testing traffic from browsers and mobile apps.

[![CI](https://github.com/qusamulab/pypproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/qusamulab/pypproxy/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pypproxy)](https://pypi.org/project/pypproxy/)
[![Python](https://img.shields.io/pypi/pyversions/pypproxy)](https://pypi.org/project/pypproxy/)

```bash
pip install pypproxy
pypproxy             # GUI mode  →  http://localhost:8081
pypproxy --mode cui  # Terminal UI
```

See the **[docs](https://qusamulab.github.io/pypproxy/)** for setup, CA installation, and feature guides.

## Features

| Category | Features |
|----------|---------|
| **Proxy** | HTTP/HTTPS MITM, WebSocket, gRPC, MQTT, HTTP/2 |
| **UI** | Sidebar navigation, dark/light mode, real-time traffic table |
| **Intercept** | Manual request review, edit headers/body, forward or drop |
| **Rules** | Block / modify / redirect by host, path, method, header, body (regex) |
| **Decode** | Auto-detect gzip/brotli, JSON, XML, JWT, Base64, multipart, Protobuf, MessagePack, CBOR |
| **Replay** | One-click replay, parallel fuzzing, Resender tab with full editor |
| **Bulk Sender** | Payload list mode + race condition test |
| **Diff** | Unified diff between any two captured entries |
| **A/B Test** | Send same request to two hosts, compare responses |
| **Macro** | Chain requests with `{{variable}}` substitution and response extraction |
| **GraphQL** | Auto-detect, introspection, schema tree, query editor |
| **OpenAPI** | Auto-generate OpenAPI 3.0 spec from captured traffic |
| **Code Gen** | Export as curl / Python requests / JavaScript fetch / HTTPie |
| **Analytics** | Per-host stats, P95/P99 latency, status distribution |
| **Security** | JWT checker, header checker, token randomness, int overflow, CORS, SSRF, redirect, IDOR |
| **Frida** | SSL pinning bypass scripts, script injection, device management |
| **Sessions** | Group entries into named sessions with persistence |
| **Report** | Export HTML or Markdown report with findings |
| **Import/Export** | HAR, pypproxy JSON, OpenAPI, rules |
| **Full-text search** | SQLite FTS5 across all captured traffic |
| **Scope** | Capture only in-scope hosts |
| **DNS spoofing** | Built-in DNS server with domain override |
| **Scripts** | Python `on_request` / `on_response` hooks |
| **Plugins** | Drop `.py` files into `~/.pypproxy/plugins/` |

## Quick start

```bash
# Install
pip install pypproxy

# Start (GUI mode)
pypproxy

# Install CA certificate (macOS)
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.pypproxy/ca-cert.pem

# Set system proxy (macOS)
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080
```

Open **http://localhost:8081** — traffic appears in real time.

## Optional: Frida integration

```bash
pip install 'pypproxy[frida]'
```

Enables one-click SSL pinning bypass and script injection from the Frida tab.

## CLI flags

```
--mode       gui (default) or cui
--port       Proxy port (default 8080)
--ui-port    Web UI port (default 8081)
--config     Path to YAML config file
--script     Path to Python script file
--ca-dir     CA cert directory (default ~/.pypproxy)
--no-db      Disable SQLite persistence
```

## License

MIT
