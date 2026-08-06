from __future__ import annotations

import importlib.util
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

from pypproxy.core.config import CONFIG_DIRNAME
from pypproxy.store.models import Entry

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    name: str
    version: str
    description: str
    path: str


class PluginBase:
    """Base class for pypproxy plugins. Override any hooks you need."""

    name: str = "unnamed"
    version: str = "0.1.0"
    description: str = ""

    def on_request(self, entry: Entry) -> Entry | None:
        """Called before a request is forwarded. Return modified entry or None to skip."""
        return entry

    def on_response(self, entry: Entry) -> Entry | None:
        """Called after a response is received. Return modified entry or None to skip."""
        return entry

    def on_entry_added(self, entry: Entry) -> None:
        """Called when an entry is added to the store."""

    def ui_tab(self) -> dict | None:
        """Return {'title': str, 'build': callable(container)} to add a UI tab, or None."""
        return None


class PluginManager:
    def __init__(self, plugin_dir: str | None = None) -> None:
        self._plugins: list[PluginBase] = []
        self._lock = threading.Lock()
        self._plugin_dir = plugin_dir or str(Path.home() / CONFIG_DIRNAME / "plugins")

    def load_directory(self) -> int:
        """Load all .py files from the plugin directory. Returns count loaded."""
        d = Path(self._plugin_dir)
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            return 0

        count = 0
        for py_file in sorted(d.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                self.load_file(str(py_file))
                count += 1
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", py_file.name, e)
        return count

    def load_file(self, path: str) -> PluginBase:
        spec = importlib.util.spec_from_file_location(f"pypproxy_plugin_{Path(path).stem}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load: {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

        # Find PluginBase subclass in module
        plugin_cls = None
        for attr in vars(mod).values():
            if isinstance(attr, type) and issubclass(attr, PluginBase) and attr is not PluginBase:
                plugin_cls = attr
                break

        if plugin_cls is None:
            raise ImportError(f"No PluginBase subclass found in {path}")

        instance = plugin_cls()
        with self._lock:
            self._plugins.append(instance)
        logger.info("Loaded plugin: %s v%s from %s", instance.name, instance.version, path)
        return instance

    def unload(self, name: str) -> None:
        with self._lock:
            self._plugins = [p for p in self._plugins if p.name != name]

    def list(self) -> list[PluginInfo]:
        with self._lock:
            return [
                PluginInfo(
                    name=p.name,
                    version=p.version,
                    description=p.description,
                    path=getattr(p, "__module__", ""),
                )
                for p in self._plugins
            ]

    def run_on_request(self, entry: Entry) -> Entry:
        with self._lock:
            plugins = list(self._plugins)
        for p in plugins:
            try:
                result = p.on_request(entry)
                if result is not None:
                    entry = result
            except Exception as e:
                logger.warning("Plugin %s on_request error: %s", p.name, e)
        return entry

    def run_on_response(self, entry: Entry) -> Entry:
        with self._lock:
            plugins = list(self._plugins)
        for p in plugins:
            try:
                result = p.on_response(entry)
                if result is not None:
                    entry = result
            except Exception as e:
                logger.warning("Plugin %s on_response error: %s", p.name, e)
        return entry

    def run_on_entry_added(self, entry: Entry) -> None:
        with self._lock:
            plugins = list(self._plugins)
        for p in plugins:
            try:
                p.on_entry_added(entry)
            except Exception as e:
                logger.warning("Plugin %s on_entry_added error: %s", p.name, e)

    def get_ui_tabs(self) -> list[dict]:
        with self._lock:
            plugins = list(self._plugins)
        tabs = []
        for p in plugins:
            try:
                tab = p.ui_tab()
                if tab:
                    tabs.append(tab)
            except Exception as e:
                logger.warning("Plugin %s ui_tab error: %s", p.name, e)
        return tabs
