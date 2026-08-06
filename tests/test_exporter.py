from __future__ import annotations

import json
from datetime import UTC, datetime

from pypproxy.exchange.exporter import (
    export_all,
    export_entries,
    export_har,
    export_rules,
    import_rules,
)
from pypproxy.rules import Action, Condition, MatchField, Rule, RuleManager
from pypproxy.store.models import Entry


def make_entry(**kwargs) -> Entry:
    e = Entry(
        method="GET",
        scheme="https",
        host="example.com",
        path="/test",
        protocol="https",
        status_code=200,
        resp_body=b'{"ok": true}',
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    for k, v in kwargs.items():
        setattr(e, k, v)
    e.id = kwargs.get("id", 1)
    return e


def test_export_entries_json():
    entries = [make_entry(), make_entry(id=2, host="other.com")]
    result = json.loads(export_entries(entries))
    assert len(result) == 2
    assert result[0]["host"] == "example.com"
    assert result[1]["host"] == "other.com"


def test_export_rules_json():
    mgr = RuleManager()
    rule = Rule(
        name="test",
        enabled=True,
        priority=5,
        action=Action.BLOCK,
        conditions=[Condition(field=MatchField.HOST, op="contains", value="ads")],
    )
    mgr.add(rule)
    result = json.loads(export_rules(mgr))
    assert len(result) == 1
    assert result[0]["name"] == "test"
    assert result[0]["action"] == "block"


def test_export_all_json():
    entries = [make_entry()]
    mgr = RuleManager()
    mgr.add(Rule(name="r", enabled=True, action=Action.PASSTHROUGH))
    result = json.loads(export_all(entries, mgr))
    assert result["version"] == 1
    assert len(result["entries"]) == 1
    assert len(result["rules"]) == 1


def test_import_rules():
    mgr = RuleManager()
    data = json.dumps(
        [
            {
                "name": "imported",
                "enabled": True,
                "priority": 1,
                "action": "block",
                "conditions": [{"field": "host", "op": "contains", "value": "spam"}],
                "modifications": [],
            }
        ]
    )
    count = import_rules(data, mgr)
    assert count == 1
    assert mgr.list()[0].name == "imported"


def test_export_har_structure():
    entries = [make_entry()]
    result = json.loads(export_har(entries))
    assert "log" in result
    assert result["log"]["version"] == "1.2"
    har_entry = result["log"]["entries"][0]
    assert har_entry["request"]["method"] == "GET"
    assert har_entry["response"]["status"] == 200


def test_export_har_body_included():
    e = make_entry()
    e.resp_body = b'{"key": "value"}'
    result = json.loads(export_har([e]))
    content = result["log"]["entries"][0]["response"]["content"]
    assert "key" in content["text"]
