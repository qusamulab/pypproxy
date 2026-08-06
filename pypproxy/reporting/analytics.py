from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from pypproxy.store.models import Entry, Filter
from pypproxy.store.store import Store


@dataclass
class HostStats:
    host: str
    count: int
    methods: dict[str, int]
    status_codes: dict[int, int]
    avg_duration_ms: float
    max_duration_ms: int
    error_rate: float  # 4xx+5xx / total
    protocols: dict[str, int]


@dataclass
class EndpointStats:
    method: str
    path: str
    count: int
    avg_duration_ms: float
    status_codes: dict[int, int]
    error_rate: float


@dataclass
class TrafficSummary:
    total: int
    hosts: list[HostStats]
    top_endpoints: list[EndpointStats]
    status_distribution: dict[str, int]  # "2xx", "3xx", "4xx", "5xx"
    method_distribution: dict[str, int]
    protocol_distribution: dict[str, int]
    avg_duration_ms: float
    p95_duration_ms: int
    p99_duration_ms: int
    errors: list[dict]  # top 5xx/4xx entries

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "hosts": [
                {
                    "host": h.host,
                    "count": h.count,
                    "methods": h.methods,
                    "status_codes": {str(k): v for k, v in h.status_codes.items()},
                    "avg_duration_ms": round(h.avg_duration_ms, 1),
                    "max_duration_ms": h.max_duration_ms,
                    "error_rate": round(h.error_rate, 3),
                    "protocols": h.protocols,
                }
                for h in self.hosts
            ],
            "top_endpoints": [
                {
                    "method": e.method,
                    "path": e.path,
                    "count": e.count,
                    "avg_duration_ms": round(e.avg_duration_ms, 1),
                    "status_codes": {str(k): v for k, v in e.status_codes.items()},
                    "error_rate": round(e.error_rate, 3),
                }
                for e in self.top_endpoints
            ],
            "status_distribution": self.status_distribution,
            "method_distribution": self.method_distribution,
            "protocol_distribution": self.protocol_distribution,
            "avg_duration_ms": round(self.avg_duration_ms, 1),
            "p95_duration_ms": self.p95_duration_ms,
            "p99_duration_ms": self.p99_duration_ms,
            "errors": self.errors,
        }


def compute(store: Store, f: Filter | None = None) -> TrafficSummary:
    entries, _ = store.list(f or Filter(), 0, 0)
    return compute_from_entries(entries)


def compute_from_entries(entries: list[Entry]) -> TrafficSummary:
    if not entries:
        return TrafficSummary(
            total=0,
            hosts=[],
            top_endpoints=[],
            status_distribution={},
            method_distribution={},
            protocol_distribution={},
            avg_duration_ms=0,
            p95_duration_ms=0,
            p99_duration_ms=0,
            errors=[],
        )

    # Per-host aggregation
    host_data: dict[str, dict] = defaultdict(
        lambda: {
            "count": 0,
            "methods": Counter(),
            "status_codes": Counter(),
            "durations": [],
            "protocols": Counter(),
        }
    )
    endpoint_data: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "count": 0,
            "durations": [],
            "status_codes": Counter(),
        }
    )
    status_dist: Counter = Counter()
    method_dist: Counter = Counter()
    proto_dist: Counter = Counter()
    all_durations: list[int] = []
    error_entries: list[Entry] = []

    for e in entries:
        h = host_data[e.host]
        h["count"] += 1
        h["methods"][e.method] += 1
        if e.status_code:
            h["status_codes"][e.status_code] += 1
        if e.duration_ms:
            h["durations"].append(e.duration_ms)
            all_durations.append(e.duration_ms)
        h["protocols"][e.protocol] += 1

        ep_key = (e.method, e.path)
        ep = endpoint_data[ep_key]
        ep["count"] += 1
        if e.duration_ms:
            ep["durations"].append(e.duration_ms)
        if e.status_code:
            ep["status_codes"][e.status_code] += 1

        if e.status_code:
            bucket = f"{e.status_code // 100}xx"
            status_dist[bucket] += 1
            if e.status_code >= 400:
                error_entries.append(e)

        method_dist[e.method] += 1
        proto_dist[e.protocol] += 1

    # Build host stats
    hosts = []
    for host, d in sorted(host_data.items(), key=lambda x: -x[1]["count"])[:20]:
        total_h = d["count"]
        errors_h = sum(v for k, v in d["status_codes"].items() if k >= 400)
        durations = d["durations"]
        hosts.append(
            HostStats(
                host=host,
                count=total_h,
                methods=dict(d["methods"]),
                status_codes=dict(d["status_codes"]),
                avg_duration_ms=sum(durations) / len(durations) if durations else 0,
                max_duration_ms=max(durations) if durations else 0,
                error_rate=errors_h / total_h if total_h else 0,
                protocols=dict(d["protocols"]),
            )
        )

    # Build endpoint stats
    endpoints = []
    for (method, path), d in sorted(endpoint_data.items(), key=lambda x: -x[1]["count"])[:20]:
        total_ep = d["count"]
        errors_ep = sum(v for k, v in d["status_codes"].items() if k >= 400)
        durations = d["durations"]
        endpoints.append(
            EndpointStats(
                method=method,
                path=path,
                count=total_ep,
                avg_duration_ms=sum(durations) / len(durations) if durations else 0,
                status_codes=dict(d["status_codes"]),
                error_rate=errors_ep / total_ep if total_ep else 0,
            )
        )

    # Percentiles
    sorted_dur = sorted(all_durations)
    n = len(sorted_dur)
    p95 = sorted_dur[int(n * 0.95)] if n > 0 else 0
    p99 = sorted_dur[int(n * 0.99)] if n > 0 else 0
    avg = sum(all_durations) / n if n > 0 else 0

    # Top errors
    errors = sorted(
        [
            {
                "id": e.id,
                "method": e.method,
                "host": e.host,
                "path": e.path,
                "status": e.status_code,
            }
            for e in error_entries
            if e.status_code >= 500
        ],
        key=lambda x: x["status"],
        reverse=True,
    )[:10]

    return TrafficSummary(
        total=len(entries),
        hosts=hosts,
        top_endpoints=endpoints,
        status_distribution=dict(status_dist),
        method_distribution=dict(method_dist),
        protocol_distribution=dict(proto_dist),
        avg_duration_ms=avg,
        p95_duration_ms=p95,
        p99_duration_ms=p99,
        errors=errors,
    )
