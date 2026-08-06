from __future__ import annotations

import importlib.util
from pathlib import Path


class ScriptEngine:
    """
    Loads a Python script and calls on_request / on_response hooks if defined.
    The script runs in its own module namespace.
    """

    def __init__(self) -> None:
        self._module = None

    def load_file(self, path: str) -> None:
        p = Path(path).resolve()
        spec = importlib.util.spec_from_file_location("pypproxy_script", p)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load script: {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        self._module = mod

    def on_request(self, method: str, host: str, path: str, body: bytes) -> bytes:
        if self._module is None:
            return body
        fn = getattr(self._module, "on_request", None)
        if fn is None:
            return body
        result = fn(method, host, path, body)
        if isinstance(result, bytes | bytearray):
            return bytes(result)
        if isinstance(result, str):
            return result.encode()
        return body

    def on_response(self, status: int, body: bytes) -> bytes:
        if self._module is None:
            return body
        fn = getattr(self._module, "on_response", None)
        if fn is None:
            return body
        result = fn(status, body)
        if isinstance(result, bytes | bytearray):
            return bytes(result)
        if isinstance(result, str):
            return result.encode()
        return body
