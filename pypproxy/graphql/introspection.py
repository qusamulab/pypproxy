from __future__ import annotations

import logging
from dataclasses import dataclass, field

from pypproxy.core.http import client as http_client

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}
"""


@dataclass
class GraphQLField:
    name: str
    description: str
    type_name: str
    args: list[str] = field(default_factory=list)
    is_deprecated: bool = False


@dataclass
class GraphQLType:
    name: str
    kind: str
    description: str
    fields: list[GraphQLField] = field(default_factory=list)


@dataclass
class GraphQLSchema:
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    types: list[GraphQLType] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "subscription_type": self.subscription_type,
            "types": [
                {
                    "name": t.name,
                    "kind": t.kind,
                    "description": t.description,
                    "fields": [
                        {
                            "name": f.name,
                            "description": f.description,
                            "type": f.type_name,
                            "args": f.args,
                            "is_deprecated": f.is_deprecated,
                        }
                        for f in t.fields
                    ],
                }
                for t in self.types
                if not t.name.startswith("__")  # exclude built-in types
            ],
        }

    def get_type(self, name: str) -> GraphQLType | None:
        for t in self.types:
            if t.name == name:
                return t
        return None

    def root_fields(self) -> list[GraphQLField]:
        """Return fields of the Query root type."""
        t = self.get_type(self.query_type or "Query")
        return t.fields if t else []

    def mutation_fields(self) -> list[GraphQLField]:
        t = self.get_type(self.mutation_type or "Mutation")
        return t.fields if t else []


async def fetch_schema(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> GraphQLSchema | None:
    """Send an introspection query and parse the schema."""
    req_headers = {"content-type": "application/json"}
    if headers:
        req_headers.update(headers)

    try:
        async with http_client(timeout) as client:
            resp = await client.post(
                url,
                json={"query": INTROSPECTION_QUERY},
                headers=req_headers,
            )
        data = resp.json()
    except Exception as e:
        logger.warning("Introspection failed for %s: %s", url, e)
        return None

    if "errors" in data and not data.get("data"):
        logger.warning("Introspection returned errors: %s", data["errors"])
        return None

    schema_data = data.get("data", {}).get("__schema", {})
    if not schema_data:
        return None

    return _parse_schema(schema_data, data)


def _parse_schema(schema_data: dict, raw: dict) -> GraphQLSchema:
    schema = GraphQLSchema(
        query_type=(schema_data.get("queryType") or {}).get("name", ""),
        mutation_type=(schema_data.get("mutationType") or {}).get("name", ""),
        subscription_type=(schema_data.get("subscriptionType") or {}).get("name", ""),
        raw=raw,
    )

    for type_data in schema_data.get("types", []):
        gql_type = GraphQLType(
            name=type_data.get("name", ""),
            kind=type_data.get("kind", ""),
            description=type_data.get("description", "") or "",
        )
        for field_data in type_data.get("fields") or []:
            gql_field = GraphQLField(
                name=field_data.get("name", ""),
                description=field_data.get("description", "") or "",
                type_name=_type_ref_to_str(field_data.get("type", {})),
                args=[a.get("name", "") for a in field_data.get("args", [])],
                is_deprecated=field_data.get("isDeprecated", False),
            )
            gql_type.fields.append(gql_field)
        schema.types.append(gql_type)

    return schema


def _type_ref_to_str(type_ref: dict) -> str:
    if not type_ref:
        return ""
    kind = type_ref.get("kind", "")
    name = type_ref.get("name", "")
    of_type = type_ref.get("ofType")

    if kind == "NON_NULL":
        return f"{_type_ref_to_str(of_type)}!"
    if kind == "LIST":
        return f"[{_type_ref_to_str(of_type)}]"
    return name or ""
