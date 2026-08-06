"""Wiring: turn resolved settings into the object graph both UI modes share.

GUI and CUI differ only in what they put in front of the user; both need the
same proxy, store, rule engine and certificate authority, built in the same
order. That assembly lives here so neither mode owns it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from pypproxy.cert.ca import CA
from pypproxy.cert.client_cert import ClientCertManager
from pypproxy.core.config import Config
from pypproxy.proxy.intercept import InterceptManager
from pypproxy.proxy.interceptor import Interceptor
from pypproxy.proxy.server import Proxy
from pypproxy.rules import RuleManager
from pypproxy.script import ScriptEngine
from pypproxy.store.scope import ScopeManager
from pypproxy.store.store import Store

logger = logging.getLogger(__name__)

DB_FILENAME = "pypproxy.db"


@dataclass(frozen=True)
class AppContext:
    """Everything a UI mode needs, already wired together."""

    config: Config
    proxy: Proxy
    store: Store
    rules: RuleManager
    scope: ScopeManager
    intercept: InterceptManager
    client_certs: ClientCertManager
    ca_cert_path: str
    db_path: str

    def describe(self) -> str:
        lines = [
            "pypproxy MITM proxy",
            f"  proxy : {self.config.proxy.addr}:{self.config.proxy.port}",
            f"  UI    : http://{self.config.ui.addr}:{self.config.ui.port}",
            f"  CA    : {self.ca_cert_path}",
        ]
        if self.db_path:
            lines.append(f"  DB    : {self.db_path}")
        lines.append("Install the CA cert in your browser/device to avoid TLS warnings.")
        return "\n".join(lines)


def build(config: Config, *, ca_dir: str = "", persist: bool = True) -> AppContext:
    """Assemble the application graph from an already-resolved `Config`."""
    root = Path(ca_dir).resolve() if ca_dir else Path(config.ca.cert_path).parent
    root.mkdir(parents=True, exist_ok=True)

    cert_path = config.ca.cert_path or str(root / "ca-cert.pem")
    key_path = config.ca.key_path or str(root / "ca-key.pem")
    ca = CA.load_or_create(cert_path, key_path)

    store = Store()
    rules = RuleManager()
    scope = ScopeManager()
    intercept = InterceptManager()

    script: ScriptEngine | None = None
    if config.script.path:
        script = ScriptEngine()
        script.load_file(config.script.path)
        logger.info("loaded script: %s", config.script.path)

    proxy = Proxy(
        ca=ca,
        interceptor=Interceptor(rules, store, scope),
        store=store,
        script=script,
        ignore=set(config.proxy.ignore),
        intercept_manager=intercept,
    )

    return AppContext(
        config=config,
        proxy=proxy,
        store=store,
        rules=rules,
        scope=scope,
        intercept=intercept,
        client_certs=ClientCertManager(),
        ca_cert_path=cert_path,
        db_path=str(root / DB_FILENAME) if persist else "",
    )


async def open_database(ctx: AppContext) -> None:
    """Attach SQLite persistence and restore previously captured traffic."""
    if not ctx.db_path:
        return
    from pypproxy.store.db import Database

    db = Database(ctx.db_path)
    await db.open()
    ctx.store.set_db(db)
    await ctx.store.load_from_db()
    logger.info("loaded %d entries from database", ctx.store.count())
