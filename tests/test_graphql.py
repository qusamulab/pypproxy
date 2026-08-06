from __future__ import annotations

import json

from pypproxy.graphql.detector import (
    extract_field_names,
    extract_operation_name,
    extract_operation_type,
    is_graphql,
    parse_operation,
)
from pypproxy.graphql.modifier import (
    add_introspection_field,
    build_mutation,
    build_query,
    set_variable,
    strip_operation_name,
)
from pypproxy.graphql.schema_store import SchemaStore
from pypproxy.store.models import Entry


def make_gql_entry(query: str, variables: dict | None = None, method: str = "POST") -> Entry:
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    return Entry(
        method=method,
        scheme="https",
        host="api.example.com",
        path="/graphql",
        req_headers={"content-type": ["application/json"]},
        req_body=body,
        protocol="https",
    )


# ---- detector ----


def test_is_graphql_post_json():
    e = make_gql_entry("query { user { id } }")
    assert is_graphql(e)


def test_is_graphql_path():
    e = Entry(method="GET", scheme="https", host="example.com", path="/graphql", protocol="https")
    assert is_graphql(e)


def test_is_graphql_content_type():
    e = Entry(
        method="POST",
        scheme="https",
        host="example.com",
        path="/api",
        req_headers={"content-type": ["application/graphql"]},
        req_body=b"{ user { id } }",
        protocol="https",
    )
    assert is_graphql(e)


def test_is_not_graphql():
    e = Entry(
        method="POST",
        scheme="https",
        host="example.com",
        path="/api/users",
        req_headers={"content-type": ["application/json"]},
        req_body=json.dumps({"name": "alice"}).encode(),
        protocol="https",
    )
    assert not is_graphql(e)


def test_extract_operation_type_query():
    assert extract_operation_type("query { user { id } }") == "query"
    assert extract_operation_type("{ user { id } }") == "query"


def test_extract_operation_type_mutation():
    assert extract_operation_type("mutation createUser { ... }") == "mutation"


def test_extract_operation_type_subscription():
    assert extract_operation_type("subscription onMessage { ... }") == "subscription"


def test_extract_operation_name():
    assert extract_operation_name("query GetUser { user { id } }") == "GetUser"
    assert extract_operation_name("mutation CreatePost { ... }") == "CreatePost"
    assert extract_operation_name("{ user { id } }") == ""


def test_extract_field_names():
    query = "query { user { id name } }"
    fields = extract_field_names(query)
    assert "user" in fields


def test_parse_operation():
    body = json.dumps(
        {
            "query": "query GetUser { user { id } }",
            "variables": {"id": "123"},
            "operationName": "GetUser",
        }
    ).encode()
    op = parse_operation(body)
    assert op["query"].strip().startswith("query")
    assert op["variables"] == {"id": "123"}
    assert op["operationName"] == "GetUser"


def test_parse_operation_invalid():
    op = parse_operation(b"not json")
    assert "not json" in op["query"]


# ---- modifier ----


def test_set_variable():
    body = json.dumps(
        {"query": "query { user(id: $id) { name } }", "variables": {"id": "old"}}
    ).encode()
    result = set_variable(body, "id", "new")
    data = json.loads(result)
    assert data["variables"]["id"] == "new"


def test_set_variable_invalid():
    result = set_variable(b"not json", "x", 1)
    assert result == b"not json"


def test_strip_operation_name():
    body = json.dumps(
        {
            "query": "query GetUser { user { id } }",
            "operationName": "GetUser",
        }
    ).encode()
    result = strip_operation_name(body)
    data = json.loads(result)
    assert "operationName" not in data


def test_build_query():
    body = build_query(["user { id name }", "posts { title }"])
    data = json.loads(body)
    assert "user" in data["query"]
    assert "posts" in data["query"]


def test_build_mutation():
    body = build_mutation("createUser", {"name": "alice"}, ["id", "name"])
    data = json.loads(body)
    assert "createUser" in data["query"]
    assert "alice" in data["query"]
    assert "id" in data["query"]


def test_add_introspection_field():
    body = json.dumps({"query": "query { user { name } }"}).encode()
    result = add_introspection_field(body)
    data = json.loads(result)
    assert "__typename" in data["query"]


# ---- schema store ----


def test_schema_store_set_get():
    from pypproxy.graphql.introspection import GraphQLSchema

    store = SchemaStore()
    schema = GraphQLSchema(query_type="Query")
    store.set("api.example.com", schema)
    result = store.get("api.example.com")
    assert result is schema


def test_schema_store_delete():
    from pypproxy.graphql.introspection import GraphQLSchema

    store = SchemaStore()
    store.set("host.com", GraphQLSchema())
    store.delete("host.com")
    assert store.get("host.com") is None


def test_schema_store_list_hosts():
    from pypproxy.graphql.introspection import GraphQLSchema

    store = SchemaStore()
    store.set("a.com", GraphQLSchema())
    store.set("b.com", GraphQLSchema())
    hosts = store.list_hosts()
    assert "a.com" in hosts
    assert "b.com" in hosts


# ---- interceptor graphql detection ----


def test_interceptor_tags_graphql():
    from pypproxy.proxy.interceptor import Interceptor
    from pypproxy.rules import RuleManager
    from pypproxy.store.store import Store

    st = Store()
    rules = RuleManager()
    ic = Interceptor(rules, st)

    body = json.dumps({"query": "query { user { id } }"}).encode()
    entry, blocked = ic.process_request(
        "POST",
        "https",
        "api.example.com",
        "/graphql",
        "",
        {"content-type": ["application/json"]},
        body,
    )
    assert not blocked
    assert "graphql" in entry.tags
    assert entry.graphql_op_type == "query"
    assert entry.protocol == "graphql"


def test_interceptor_mutation_tagged():
    from pypproxy.proxy.interceptor import Interceptor
    from pypproxy.rules import RuleManager
    from pypproxy.store.store import Store

    st = Store()
    ic = Interceptor(RuleManager(), st)
    body = json.dumps({"query": "mutation CreateUser { createUser { id } }"}).encode()
    entry, _ = ic.process_request(
        "POST",
        "https",
        "api.example.com",
        "/graphql",
        "",
        {"content-type": ["application/json"]},
        body,
    )
    assert entry.graphql_op_type == "mutation"
    assert entry.graphql_operation == "CreateUser"
