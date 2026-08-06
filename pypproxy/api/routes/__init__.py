from pypproxy.api.routes import (
    exchange,
    graphql,
    reporting,
    rules,
    security,
    tools,
    traffic,
)

#: Every router the API exposes, in the order they are mounted.
ALL_ROUTERS = [
    traffic.router,
    traffic.ws_router,
    rules.router,
    tools.router,
    security.router,
    exchange.router,
    reporting.router,
    graphql.router,
]

__all__ = ["ALL_ROUTERS"]
