"""Minimal, deterministic YAML emitter for the plain data yard renders.

Only dicts, lists, str, int, float, bool and None are supported. Strings are
always double-quoted (JSON escaping is valid YAML), so no value can be
misread as another type or inject structure.
"""

from __future__ import annotations

import json
from typing import Any


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    raise TypeError(f"unsupported YAML scalar: {type(value).__name__}")


def _emit(value: Any, indent: int, out: list[str]) -> None:
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            out[-1] += " {}"
            return
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("YAML keys must be strings")
            k = key if key.replace("_", "a").replace("-", "a").isalnum() else json.dumps(key)
            if isinstance(item, (dict, list)) and item:
                out.append(f"{pad}{k}:")
                _emit(item, indent + 1, out)
            elif isinstance(item, (dict, list)):
                out.append(f"{pad}{k}: {'{}' if isinstance(item, dict) else '[]'}")
            else:
                out.append(f"{pad}{k}: {_scalar(item)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item:
                first = True
                for key, sub in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    first = False
                    k = key if key.replace("_", "a").replace("-", "a").isalnum() else json.dumps(key)
                    if isinstance(sub, (dict, list)) and sub:
                        out.append(f"{prefix}{k}:")
                        _emit(sub, indent + 2, out)
                    elif isinstance(sub, (dict, list)):
                        out.append(f"{prefix}{k}: {'{}' if isinstance(sub, dict) else '[]'}")
                    else:
                        out.append(f"{prefix}{k}: {_scalar(sub)}")
            elif isinstance(item, list) and item:
                out.append(f"{pad}-")
                _emit(item, indent + 1, out)
            else:
                out.append(f"{pad}- {_scalar(item) if not isinstance(item, (dict, list)) else ('{}' if isinstance(item, dict) else '[]')}")
    else:
        out.append(f"{pad}{_scalar(value)}")


def dumps(value: Any) -> str:
    if not isinstance(value, dict):
        raise TypeError("top-level YAML value must be a mapping")
    out: list[str] = []
    _emit(value, 0, out)
    return "\n".join(out) + "\n"
