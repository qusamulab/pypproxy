# Configuration

pypproxy can be configured via CLI flags or a YAML file. CLI flags take precedence over the config file.

## YAML config file

```bash
uv run python -m pypproxy --config pypproxy.yaml
```

### Full example

```yaml
proxy:
  addr: "0.0.0.0"
  port: 8080
  # Hosts to pass through without MITM (certificate pinning, internal services, etc.)
  ignore:
    - pinned.example.com
    - internal.corp
  # Maximum body size to capture, in bytes
  max_body: 1048576  # 1 MB

ca:
  cert_path: /custom/ca-cert.pem
  key_path:  /custom/ca-key.pem

ui:
  addr: "0.0.0.0"
  port: 8081

script:
  path: /path/to/script.py
```

## Field reference

### `proxy`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `addr` | string | `0.0.0.0` | Proxy listen address |
| `port` | int | `8080` | Proxy port |
| `ignore` | list | `[]` | Hosts to tunnel without MITM |
| `max_body` | int | `1048576` | Max body bytes to capture |

### `ca`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cert_path` | string | `~/.pypproxy/ca-cert.pem` | CA certificate path |
| `key_path` | string | `~/.pypproxy/ca-key.pem` | CA private key path |

### `ui`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `addr` | string | `0.0.0.0` | Web UI / API listen address |
| `port` | int | `8081` | Web UI / API port |

### `script`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | — | Python script path |

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `gui` | UI mode: `gui` or `cui` |
| `--addr` | `0.0.0.0` | Proxy listen address |
| `--port` | `8080` | Proxy port |
| `--ui-addr` | `0.0.0.0` | Web UI / API address |
| `--ui-port` | `8081` | Web UI / API port |
| `--config` | — | Config file path |
| `--script` | — | Python script path |
| `--ca-dir` | `~/.pypproxy` | Directory to store CA cert and key |
