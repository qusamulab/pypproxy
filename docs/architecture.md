# Architecture

## Overview

```
┌───────────────────────────────────────────────────────────────┐
│  Client (browser / mobile app)                                │
└─────────────────────────┬─────────────────────────────────────┘
                          │ HTTP / CONNECT
┌─────────────────────────▼─────────────────────────────────────┐
│  proxy/server.py  (port :8080)   asyncio TCP server           │
│  ├─ HTTP    → intercept → forward upstream (httpx, HTTP/2)    │
│  ├─ CONNECT → TLS termination (MITM)                          │
│  │     ├─ HTTP/HTTPS → intercept → forward upstream           │
│  │     ├─ WebSocket  → protocols/ws.py                        │
│  │     ├─ gRPC       → protocols/grpc.py                      │
│  │     └─ MQTT       → protocols/mqtt.py                      │
│  └─ ignored hosts → raw TCP tunnel (passthrough)              │
└──────────────┬───────────────────────┬────────────────────────┘
               │                       │
┌──────────────▼─────┐   ┌─────────────▼─────────────────────┐
│  cert/ca.py        │   │  proxy/interceptor.py             │
│  CA + per-host TLS │   │  apply rules, record entries      │
│  SSL Context cache │   └─────────────┬─────────────────────┘
│                    │                 │
│  cert/             │   ┌─────────────▼─────────────────────┐
│  client_cert.py    │   │  store/store.py                   │
│  Mutual TLS certs  │   │  in-memory store + SQLite persist │
└────────────────────┘   │  asyncio pub/sub                  │
                         └─────────────┬─────────────────────┘
                                       │
          ┌────────────────────────────┼──────────────────────┐
          │                            │                      │
┌─────────▼──────────┐   ┌─────────────▼─────────┐  ┌─────────▼─────────┐
│  api/              │   │  ui/app.py            │  │  ui/cui.py        │
│  FastAPI routers   │   │  NiceGUI shell        │  │  rich terminal UI │
│  + WebSocket /ws   │   │  + ui/tabs/*          │  │  (CUI mode)       │
└────────────────────┘   └───────────────────────┘  └───────────────────┘
```

`cli.py` parses arguments, `bootstrap.py` assembles the graph above into an
`AppContext`, and both UI modes consume that same context.

## Package overview

All paths below are relative to the `pypproxy/` package.

| Module | Responsibility |
|--------|----------------|
| `cli` | Argument parsing and mode dispatch (`python -m pypproxy`) |
| `bootstrap` | Builds the `AppContext` both UI modes share |
| `core/config` | YAML config loading and saving |
| `core/codec` | Content-encoding decode (gzip/br/deflate); binary formats (Protobuf/MessagePack/CBOR) |
| `core/http` | Shared httpx client factory, header flattening, URL building |
| `proxy/server` | asyncio TCP server; HTTP forwarding; TLS MITM for CONNECT; raw tunnel for ignored hosts |
| `proxy/messages` | Raw HTTP/1.1 request parsing and response framing |
| `proxy/interceptor` | Apply rules to requests and responses; record entries in the store |
| `proxy/intercept` | Manual intercept manager; pause requests for user review |
| `rules` | Rule evaluation engine; condition matching; priority ordering |
| `cert/ca` | CA certificate generation; per-host SSL Context cache |
| `cert/client_cert` | Client certificate management for mutual TLS |
| `store/models` | `Entry` and `Filter`, the shared traffic model |
| `store/store` | Thread-safe in-memory traffic store; asyncio pub/sub |
| `store/db` | SQLite persistence via aiosqlite; load/save entries |
| `store/filter_parser` | Filter expression parser (`host == x && method == POST`) |
| `store/scope` | Host scoping — decide which traffic gets recorded |
| `api/` | FastAPI routers (`routes/`), dependencies (`deps`), request schemas |
| `ui/app` | NiceGUI shell: sidebar, toolbar, live traffic feed |
| `ui/pages` | Page registry mapping nav items to lazily imported tab builders |
| `ui/workspace` | State shared across pages (filter, pending entry, diff selection) |
| `ui/traffic` | Traffic table, row context menu, detail pane |
| `ui/tabs/` | One module per tool tab |
| `ui/settings` | Settings page (rules, SSL passthrough, DNS, ports, client certs) |
| `ui/cui` | rich terminal UI (CUI mode) |
| `protocols/ws` | WebSocket frame relay and logging |
| `protocols/grpc` | gRPC length-prefix frame decoding |
| `protocols/mqtt` | MQTT frame decoding and detection |
| `script` | Python script engine; `on_request` / `on_response` hooks |
| `tools/` | replay, bulk sender, macro runner, A/B test, code generation |
| `security/` | Header/JWT/IDOR/overflow checks, randomness analysis, active scanner |
| `reporting/` | HTML & Markdown reports, OpenAPI generation, traffic analytics |
| `exchange/` | JSON/HAR export and rule import/export |
| `graphql/` | GraphQL detection, introspection, schema store, query modification |
| `frida/` | Frida device control, hook generation, SSL pinning bypass |
| `dns` | Built-in DNS server with domain spoofing |
| `session` | Named groupings of captured entries |

## Key design decisions

### asyncio TCP server

The proxy is a raw `asyncio.start_server` TCP server that parses HTTP manually.
This lets a single connection handle HTTP/1.1 keep-alive, CONNECT tunnels, WebSocket upgrades, and MQTT detection without switching servers mid-connection.

### TLS termination with `loop.start_tls()`

After responding `200 Connection Established` to a CONNECT request, pypproxy calls `loop.start_tls()` to upgrade the existing asyncio transport to TLS server-side. Per-host certificates are cached as `ssl.SSLContext` objects.

### SQLite persistence via aiosqlite

All captured traffic is stored in memory for fast access. Writes to SQLite are fire-and-forget via `asyncio.run_coroutine_threadsafe`. On startup, `store.load_from_db()` restores prior sessions. The DB path defaults to `~/.pypproxy/pypproxy.db`.

### Store pub/sub

The `Store` maintains a list of `asyncio.Queue` subscribers. The proxy calls `loop.call_soon_threadsafe` to push entries into queues from the proxy coroutine. The UI polls each queue to receive live updates without blocking.

### HTTP/2

All upstream requests use `httpx` with `http2=True`. httpx negotiates HTTP/2 via ALPN where the server supports it and falls back to HTTP/1.1 transparently.

### Filter expression engine

The filter bar in the UI accepts a structured expression parsed by `store/filter_parser.py`. The parser tokenizes `field op value` conditions and evaluates them with AND/OR short-circuit logic against `Entry` objects in memory.

### Binary format detection

`core/codec.py` implements `sniff_content_type()` which combines Content-Type inspection with a JSON parse attempt and a binary entropy heuristic to guess the best display mode. Protobuf decoding uses wire-type heuristics without requiring a `.proto` schema.

### GUI / CUI startup

In **GUI mode**, `ui.run()` owns the event loop and the proxy is launched via `nicegui_app.on_startup`. In **CUI mode**, `asyncio.run()` owns the loop and `asyncio.gather` runs the proxy, uvicorn API server, and rich TUI concurrently.
