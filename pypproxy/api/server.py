"""The pypproxy HTTP API.

In CUI mode `build_api` returns an app that uvicorn serves directly; in GUI mode
the same routers are mounted into NiceGUI's app via `register_routes`, so both
front-ends expose exactly one API surface.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pypproxy.api.deps import ApiState, configure
from pypproxy.api.routes import ALL_ROUTERS
from pypproxy.bootstrap import AppContext
from pypproxy.graphql.schema_store import SchemaStore


def build_api(ctx: AppContext) -> FastAPI:
    """Install the application state and return a standalone API app."""
    configure(
        ApiState(
            store=ctx.store,
            rules=ctx.rules,
            scope=ctx.scope,
            schemas=SchemaStore(),
        )
    )

    app = FastAPI(title="pypproxy API")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    register_routes(app)
    return app


def register_routes(target_app: FastAPI) -> None:
    """Mount every API router onto an existing FastAPI/NiceGUI app."""
    for router in ALL_ROUTERS:
        target_app.include_router(router)
