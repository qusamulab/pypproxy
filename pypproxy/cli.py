from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from pypproxy import __version__, bootstrap
from pypproxy.bootstrap import AppContext
from pypproxy.core.config import Config
from pypproxy.proxy.server import Proxy

logger = logging.getLogger("pypproxy")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="pypproxy", description="pypproxy MITM proxy")
    p.add_argument("--version", action="version", version=f"pypproxy {__version__}")
    p.add_argument(
        "--mode",
        choices=["gui", "cui"],
        default="gui",
        help="UI mode: gui (browser, default) or cui (terminal)",
    )
    p.add_argument("--addr", default="", help="proxy listen address")
    p.add_argument("--port", type=int, default=0, help="proxy port (default 8080)")
    p.add_argument("--ui-addr", default="", help="web UI / API listen address")
    p.add_argument("--ui-port", type=int, default=0, help="web UI port (default 8081)")
    p.add_argument("--config", default="", help="path to YAML config file")
    p.add_argument("--script", default="", help="path to Python script file")
    p.add_argument("--ca-dir", default="", help="directory to store CA cert/key")
    p.add_argument("--no-db", action="store_true", help="disable SQLite persistence")
    return p.parse_args(argv)


def resolve_config(args: argparse.Namespace) -> Config:
    """Load the config file (if any) and apply command-line overrides on top."""
    cfg = Config.load(str(Path(args.config).resolve())) if args.config else Config.default()

    if args.addr:
        cfg.proxy.addr = args.addr
    if args.port:
        cfg.proxy.port = args.port
    if args.ui_addr:
        cfg.ui.addr = args.ui_addr
    if args.ui_port:
        cfg.ui.port = args.ui_port
    if args.script:
        cfg.script.path = str(Path(args.script).resolve())

    return cfg


async def serve_proxy(proxy: Proxy, host: str, port: int) -> None:
    try:
        server = await asyncio.start_server(proxy.handle, host, port)
    except OSError as e:
        logger.error("Failed to start proxy on %s:%d — %s", host, port, e)
        logger.error("Is another process already using port %d? Run: lsof -i :%d", port, port)
        return
    logger.info("proxy listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


def run_gui(ctx: AppContext) -> None:
    from nicegui import app as nicegui_app
    from nicegui import ui

    from pypproxy.api.server import build_api, register_routes
    from pypproxy.ui.app import build_ui

    build_api(ctx)
    register_routes(nicegui_app)
    build_ui(ctx)

    async def startup() -> None:
        ctx.store.set_loop(asyncio.get_event_loop())
        await bootstrap.open_database(ctx)
        asyncio.ensure_future(serve_proxy(ctx.proxy, ctx.config.proxy.addr, ctx.config.proxy.port))

    nicegui_app.on_startup(startup)

    ui.run(
        host=ctx.config.ui.addr,
        port=ctx.config.ui.port,
        title="pypproxy",
        dark=True,
        reload=False,
        show=False,
    )


def run_cui(ctx: AppContext) -> None:
    import uvicorn

    from pypproxy.api.server import build_api
    from pypproxy.ui.cui import run_cui as render_cui

    api_app = build_api(ctx)

    async def _main() -> None:
        ctx.store.set_loop(asyncio.get_event_loop())
        await bootstrap.open_database(ctx)

        uv_server = uvicorn.Server(
            uvicorn.Config(
                api_app,
                host=ctx.config.ui.addr,
                port=ctx.config.ui.port,
                log_level="warning",
            )
        )

        await asyncio.gather(
            serve_proxy(ctx.proxy, ctx.config.proxy.addr, ctx.config.proxy.port),
            uv_server.serve(),
            render_cui(
                ctx.store,
                f"{ctx.config.proxy.addr}:{ctx.config.proxy.port}",
                ctx.config.ui.port,
            ),
        )

    asyncio.run(_main())


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    args = parse_args(argv)
    ctx = bootstrap.build(
        resolve_config(args),
        ca_dir=args.ca_dir,
        persist=not args.no_db,
    )
    print(ctx.describe())

    if args.mode == "cui":
        run_cui(ctx)
    else:
        run_gui(ctx)


if __name__ == "__main__":
    main()
