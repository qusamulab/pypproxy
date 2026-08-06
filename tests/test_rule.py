from __future__ import annotations

from pypproxy.rules import (
    Action,
    Condition,
    MatchContext,
    MatchField,
    Modification,
    Rule,
    RuleManager,
)


def make_ctx(**kwargs) -> MatchContext:
    defaults = {"method": "GET", "host": "example.com", "path": "/", "headers": {}, "body": b""}
    defaults.update(kwargs)
    return MatchContext(**defaults)


def make_rule(**kwargs) -> Rule:
    defaults = {
        "name": "test",
        "enabled": True,
        "priority": 0,
        "action": Action.BLOCK,
        "conditions": [],
    }
    defaults.update(kwargs)
    return Rule(**defaults)


def test_match_returns_none_when_no_rules():
    mgr = RuleManager()
    assert mgr.match(make_ctx()) is None


def test_match_by_host_contains():
    mgr = RuleManager()
    rule = make_rule(conditions=[Condition(field=MatchField.HOST, op="contains", value="example")])
    mgr.add(rule)
    assert mgr.match(make_ctx(host="example.com")) is rule
    assert mgr.match(make_ctx(host="other.com")) is None


def test_disabled_rule_is_skipped():
    mgr = RuleManager()
    rule = make_rule(
        enabled=False,
        conditions=[Condition(field=MatchField.HOST, op="contains", value="example")],
    )
    mgr.add(rule)
    assert mgr.match(make_ctx()) is None


def test_priority_ordering():
    mgr = RuleManager()
    low = make_rule(
        name="low",
        priority=1,
        conditions=[Condition(field=MatchField.PATH, op="equals", value="/")],
    )
    high = make_rule(
        name="high",
        priority=10,
        conditions=[Condition(field=MatchField.PATH, op="equals", value="/")],
    )
    mgr.add(low)
    mgr.add(high)
    matched = mgr.match(make_ctx(path="/"))
    assert matched.name == "high"


def test_negate_condition():
    mgr = RuleManager()
    rule = make_rule(
        conditions=[Condition(field=MatchField.HOST, op="equals", value="example.com", negate=True)]
    )
    mgr.add(rule)
    assert mgr.match(make_ctx(host="other.com")) is rule
    assert mgr.match(make_ctx(host="example.com")) is None


def test_regex_op():
    mgr = RuleManager()
    rule = make_rule(conditions=[Condition(field=MatchField.PATH, op="regex", value=r"^/api/v\d+")])
    mgr.add(rule)
    assert mgr.match(make_ctx(path="/api/v2/users")) is rule
    assert mgr.match(make_ctx(path="/static/main.js")) is None


def test_delete_rule():
    mgr = RuleManager()
    rule = make_rule(conditions=[Condition(field=MatchField.HOST, op="contains", value="x")])
    mgr.add(rule)
    mgr.delete(rule.id)
    assert mgr.match(make_ctx(host="x.com")) is None


def test_rule_to_dict_and_from_dict():
    rule = Rule(
        id=1,
        name="round-trip",
        enabled=True,
        priority=5,
        action=Action.MODIFY,
        conditions=[Condition(field=MatchField.METHOD, op="equals", value="POST")],
        modifications=[Modification(target="req_header", key="X-Test", value="1", operation="set")],
    )
    d = rule.to_dict()
    restored = Rule.from_dict(d)
    assert restored.name == rule.name
    assert restored.action == rule.action
    assert len(restored.conditions) == 1
    assert restored.conditions[0].field == MatchField.METHOD
    assert len(restored.modifications) == 1
