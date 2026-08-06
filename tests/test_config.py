from __future__ import annotations

from pathlib import Path

import yaml

from pypproxy.core.config import CONFIG_DIRNAME, Config


def test_default_uses_pypproxy_home():
    cfg = Config.default()
    assert cfg.ca.cert_path == str(Path.home() / CONFIG_DIRNAME / "ca-cert.pem")
    assert cfg.ca.key_path == str(Path.home() / CONFIG_DIRNAME / "ca-key.pem")


def test_load_missing_file_returns_defaults(tmp_path):
    cfg = Config.load(str(tmp_path / "nope.yaml"))
    assert cfg.proxy.port == 8080


def test_load_coerces_numeric_strings(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.dump({"proxy": {"port": "9090", "max_body": "2048"}, "ui": {"port": "1"}}))
    cfg = Config.load(str(p))
    assert cfg.proxy.port == 9090
    assert cfg.proxy.max_body == 2048
    assert cfg.ui.port == 1


def test_load_resolves_paths(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.dump({"ca": {"cert_path": "certs/ca.pem"}, "script": {"path": "s.py"}}))
    cfg = Config.load(str(p))
    assert Path(cfg.ca.cert_path).is_absolute()
    assert Path(cfg.script.path).is_absolute()


def test_load_ignores_unknown_keys(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.dump({"proxy": {"port": 1234, "bogus": True}, "nonsense": {"a": 1}}))
    cfg = Config.load(str(p))
    assert cfg.proxy.port == 1234
    assert not hasattr(cfg.proxy, "bogus")


def test_save_round_trip(tmp_path):
    cfg = Config.default()
    cfg.proxy.port = 7070
    cfg.proxy.ignore = ["a.com", "b.com"]
    out = tmp_path / "out.yaml"
    cfg.save(str(out))

    reloaded = Config.load(str(out))
    assert reloaded.proxy.port == 7070
    assert reloaded.proxy.ignore == ["a.com", "b.com"]
