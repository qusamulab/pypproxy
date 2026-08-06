from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Entry:
    id: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Request
    method: str = ""
    scheme: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    req_headers: dict[str, list[str]] = field(default_factory=dict)
    req_body: bytes = b""

    # Response
    status_code: int = 0
    resp_headers: dict[str, list[str]] = field(default_factory=dict)
    resp_body: bytes = b""
    duration_ms: int = 0

    # Meta
    protocol: str = "http"
    tags: list[str] = field(default_factory=list)
    modified: bool = False
    color: str = ""  # row highlight color (hex or name)
    graphql_operation: str = ""  # operation name if GraphQL
    graphql_op_type: str = ""  # query | mutation | subscription

    @property
    def base_url(self) -> str:
        """Request URL without the query string."""
        return f"{self.scheme}://{self.host}{self.path}"

    @property
    def url(self) -> str:
        """Full request URL, query string included."""
        return self.base_url + (f"?{self.query}" if self.query else "")

    def summary(self) -> str:
        """One-line human label, e.g. `#12 GET https://example.com/api`."""
        return f"#{self.id} {self.method} {self.base_url}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "path": self.path,
            "query": self.query,
            "req_headers": self.req_headers,
            "req_body": base64.b64encode(self.req_body).decode() if self.req_body else "",
            "status_code": self.status_code,
            "resp_headers": self.resp_headers,
            "resp_body": base64.b64encode(self.resp_body).decode() if self.resp_body else "",
            "duration_ms": self.duration_ms,
            "protocol": self.protocol,
            "tags": self.tags,
            "modified": self.modified,
            "color": self.color,
            "graphql_operation": self.graphql_operation,
            "graphql_op_type": self.graphql_op_type,
        }


@dataclass
class Filter:
    method: str = ""
    host: str = ""
    search: str = ""
    protocol: str = ""
    expression: str = ""  # PacketProxy-style filter expression

    def matches(self, entry: Entry) -> bool:
        # Advanced expression takes precedence when set
        if self.expression:
            from pypproxy.store.filter_parser import FilterExpression

            return FilterExpression(self.expression).matches(entry)
        if self.method and entry.method != self.method:
            return False
        if self.host and entry.host != self.host:
            return False
        if self.protocol and entry.protocol != self.protocol:
            return False
        return not (self.search and self.search.lower() not in (entry.host + entry.path).lower())
