"""
VulneraX — Plugin System
==========================
Dynamically discovers and loads scanner plugins from the plugins/ directory.

How it works
------------
1. Scans every .py file in the plugins/ directory (non-recursive).
2. Imports each module and inspects its classes.
3. Any class that is a concrete subclass of PluginBase is registered.
4. discover_plugins() returns the list of ready-to-instantiate classes.

Adding a plugin
---------------
1. Create a .py file in plugins/.
2. Define a class that inherits from PluginBase.
3. Implement name, description, author, version attributes and run().
4. VulneraX will auto-discover it on next launch.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import List, Type

from utils.logger import get_logger

log = get_logger("vulnerax.plugins")

_PLUGINS_DIR = Path(__file__).parent
_EXCLUDE = {"__init__", "plugin_base"}


def discover_plugins() -> List[Type]:
    """
    Discover all concrete PluginBase subclasses in the plugins/ directory.

    Returns:
        List of (uninstantiated) plugin classes.
    """
    # Import lazily to avoid circular imports
    from plugins.plugin_base import PluginBase

    found: List[Type] = []

    for py_file in sorted(_PLUGINS_DIR.glob("*.py")):
        module_name = py_file.stem
        if module_name in _EXCLUDE:
            continue

        full_module_name = f"plugins.{module_name}"
        try:
            if full_module_name in sys.modules:
                module = sys.modules[full_module_name]
            else:
                spec = importlib.util.spec_from_file_location(
                    full_module_name, py_file
                )
                module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
                spec.loader.exec_module(module)  # type: ignore[union-attr]
                sys.modules[full_module_name] = module

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, PluginBase)
                    and obj is not PluginBase
                    and not inspect.isabstract(obj)
                ):
                    log.debug("Discovered plugin: %s v%s by %s", obj.name, obj.version, obj.author)
                    found.append(obj)

        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to load plugin from %s: %s", py_file.name, exc)

    if found:
        log.info("Plugin system: %d plugin(s) loaded.", len(found))
    else:
        log.debug("Plugin system: no external plugins found.")

    return found


def list_plugins() -> List[dict]:
    """Return metadata dicts for all discovered plugins (used by CLI)."""
    from plugins.plugin_base import PluginBase
    classes = discover_plugins()
    return [
        {
            "name": cls.name,
            "description": cls.description,
            "author": cls.author,
            "version": cls.version,
        }
        for cls in classes
    ]
