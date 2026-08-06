# Python Scripting

Scripts let you transform requests and responses with arbitrary Python logic — no DSL, no restarts needed for simple changes.

## Loading a script

```bash
uv run python -m pypproxy --script /path/to/script.py
```

Or via config file:

```yaml
script:
  path: /path/to/script.py
```

## Hook functions

Define any of these functions in your script. pypproxy calls them automatically.

### `on_request(method, host, path, body)`

Called before a request is forwarded upstream. The return value replaces the request body.

```python
def on_request(method: str, host: str, path: str, body: bytes) -> bytes:
    return body
```

### `on_response(status, body)`

Called before a response is returned to the client. The return value replaces the response body.

```python
def on_response(status: int, body: bytes) -> bytes:
    return body
```

## Examples

### Replace a string in all responses

```python
def on_response(status: int, body: bytes) -> bytes:
    return body.replace(b"https://prod.example.com", b"https://staging.example.com")
```

### Log every request

```python
import sys

def on_request(method: str, host: str, path: str, body: bytes) -> bytes:
    print(f"{method} {host}{path}", file=sys.stderr)
    return body
```

### Rewrite a JSON response

```python
import json

def on_response(status: int, body: bytes) -> bytes:
    if status != 200:
        return body
    try:
        data = json.loads(body)
        data["debug"] = True
        return json.dumps(data).encode()
    except Exception:
        return body
```

### Process only specific paths

```python
_path = ""

def on_request(method: str, host: str, path: str, body: bytes) -> bytes:
    global _path
    _path = path
    return body

def on_response(status: int, body: bytes) -> bytes:
    if "/api/users" in _path:
        return body.replace(b"admin", b"user")
    return body
```

## Notes

- The script is loaded once at startup. Restart pypproxy to pick up changes.
- Both hooks may be called concurrently from multiple requests. Protect shared state with a lock if needed.
- Use `sys.stderr` for logging to avoid mixing output with pypproxy's own logs.
- The full Python standard library and any packages in the project's virtualenv are available.
