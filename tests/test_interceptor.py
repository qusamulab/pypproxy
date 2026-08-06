from __future__ import annotations

import time

from pypproxy.proxy.interceptor import Interceptor
from pypproxy.rules import Action, Condition, MatchField, Modification, Rule, RuleManager
from pypproxy.store.store import Store


def make_interceptor() -> tuple[Interceptor, Store, RuleManager]:
    store = Store()
    rules = RuleManager()
    return Interceptor(rules, store), store, rules


def test_process_request_records_entry():
    ic, store, _ = make_interceptor()
    entry, blocked = ic.process_request("GET", "https", "example.com", "/", "", {}, b"")
    assert not blocked
    assert store.get(entry.id) is entry
    assert entry.method == "GET"


def test_process_request_block_rule():
    ic, store, rules = make_interceptor()
    rule = Rule(
        name="block all",
        enabled=True,
        priority=1,
        action=Action.BLOCK,
        conditions=[Condition(field=MatchField.HOST, op="contains", value="example")],
    )
    rules.add(rule)
    entry, blocked = ic.process_request("GET", "https", "example.com", "/", "", {}, b"")
    assert blocked
    assert "blocked" in entry.tags


def test_process_request_modify_rule():
    ic, store, rules = make_interceptor()
    rule = Rule(
        name="add header",
        enabled=True,
        priority=1,
        action=Action.MODIFY,
        conditions=[Condition(field=MatchField.HOST, op="contains", value="example")],
        modifications=[
            Modification(target="req_header", key="x-debug", value="1", operation="set")
        ],
    )
    rules.add(rule)
    entry, blocked = ic.process_request("GET", "https", "example.com", "/", "", {}, b"")
    assert not blocked
    assert entry.modified


def test_process_response_records():
    ic, store, _ = make_interceptor()
    entry, _ = ic.process_request("GET", "https", "example.com", "/", "", {}, b"")
    start = time.monotonic()
    ic.process_response(entry, 200, {"content-type": ["text/plain"]}, b"hello", start)
    assert entry.status_code == 200
    assert entry.resp_body == b"hello"
    assert entry.duration_ms >= 0
