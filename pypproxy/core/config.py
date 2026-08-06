from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

#: Where the CA keypair and the traffic database live by default.
CONFIG_DIRNAME = ".pypproxy"

#: Config values that name a file and are resolved relative to the CWD.
_PATH_KEYS = frozenset({"cert_path", "key_path", "path"})


@dataclass
class ProxyConfig:
    addr: str = "0.0.0.0"
    port: int = 8080
    ignore: list[str] = field(default_factory=list)
    max_body: int = 1024 * 1024  # 1MB


@dataclass
class CAConfig:
    cert_path: str = ""
    key_path: str = ""


@dataclass
class UIConfig:
    addr: str = "0.0.0.0"
    port: int = 8081


@dataclass
class ScriptConfig:
    path: str = ""


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    ca: CAConfig = field(default_factory=CAConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    script: ScriptConfig = field(default_factory=ScriptConfig)

    @classmethod
    def default(cls) -> Config:
        cfg = cls()
        root = Path.home() / CONFIG_DIRNAME
        cfg.ca.cert_path = str(root / "ca-cert.pem")
        cfg.ca.key_path = str(root / "ca-key.pem")
        return cfg

    @classmethod
    def load(cls, path: str) -> Config:
        """Read a YAML config, layering it over the defaults. Missing file is fine."""
        cfg = cls.default()
        p = Path(path)
        if not p.exists():
            return cfg

        with p.open() as f:
            data = yaml.safe_load(f) or {}

        for section in fields(cls):
            _apply(getattr(cfg, section.name), data.get(section.name) or {}, section.name)
        return cfg

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            yaml.dump(asdict(self), f, default_flow_style=False)


def _apply(section: Any, values: dict, section_name: str) -> None:
    known = {f.name: f.type for f in fields(section)}
    for key, raw in values.items():
        if key not in known:
            logger.warning("ignoring unknown config key %s.%s", section_name, key)
            continue
        setattr(section, key, _coerce(key, known[key], raw))


def _coerce(key: str, declared_type: Any, raw: Any) -> Any:
    if key in _PATH_KEYS:
        return str(Path(raw).resolve())
    if declared_type in (int, "int"):
        return int(raw)
    return raw
