"""Tool registry: the Python stand-in for Semantic Kernel [KernelFunction] plugins.

A tool is a plain function ``fn(ctx, **kwargs)`` decorated with ``@tool``.
Parameter descriptions come from ``Annotated[type, "description"]`` hints, and
the JSON schema handed to the model (and to MCP clients) is generated from them.
A trailing underscore is dropped from the public name (``from_`` -> ``from``).
"""
from __future__ import annotations

import inspect
import json
import types
import typing
from dataclasses import dataclass, field
from typing import Any, Callable

TOOLS: dict[str, "ToolDef"] = {}


@dataclass
class ToolDef:
    name: str
    plugin: str
    description: str
    fn: Callable[..., Any]
    params: dict[str, dict[str, Any]]           # public name -> {schema, py_name, required}
    progress: str = ""
    # Set for tools proxied from a remote MCP server: {"server", "remote_name", "read_only", "pin"}.
    remote: dict[str, Any] | None = None

    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {k: v["schema"] for k, v in self.params.items()},
            "required": [k for k, v in self.params.items() if v["required"]],
            "additionalProperties": False,
        }


def _schema_for(tp: Any) -> dict[str, Any]:
    origin = typing.get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        inner = [a for a in typing.get_args(tp) if a is not type(None)]
        return _schema_for(inner[0]) if inner else {"type": "string"}
    if origin in (list, typing.List):
        (item,) = typing.get_args(tp) or (str,)
        return {"type": "array", "items": _schema_for(item)}
    return {str: {"type": "string"}, int: {"type": "integer"}, float: {"type": "number"},
            bool: {"type": "boolean"}}.get(tp, {"type": "string"})


def tool(plugin: str, description: str, progress: str = "") -> Callable:
    def decorate(fn: Callable) -> Callable:
        hints = typing.get_type_hints(fn, include_extras=True)
        params: dict[str, dict[str, Any]] = {}
        for p in list(inspect.signature(fn).parameters.values())[1:]:  # skip ctx
            hint = hints.get(p.name, str)
            desc = ""
            if typing.get_origin(hint) is typing.Annotated:
                base, *meta = typing.get_args(hint)
                desc = next((m for m in meta if isinstance(m, str)), "")
                hint = base
            schema = _schema_for(hint)
            if desc:
                schema = {**schema, "description": desc}
            public = p.name.rstrip("_")
            params[public] = {"schema": schema, "py_name": p.name,
                              "required": p.default is inspect.Parameter.empty}
        TOOLS[fn.__name__] = ToolDef(fn.__name__, plugin, description, fn, params, progress)
        return fn
    return decorate


class ToolArgumentError(ValueError):
    pass


def coerce_arguments(td: ToolDef, raw: dict[str, Any] | None) -> dict[str, Any]:
    """Validate model-supplied arguments against the schema. Unknown keys are rejected."""
    raw = dict(raw or {})
    unknown = sorted(set(raw) - set(td.params))
    if unknown:
        raise ToolArgumentError(f"Unknown argument(s): {', '.join(unknown)}")
    out: dict[str, Any] = {}
    for public, spec in td.params.items():
        if public not in raw or raw[public] is None:
            if spec["required"]:
                raise ToolArgumentError(f"Missing required argument '{public}'")
            continue
        value, kind = raw[public], spec["schema"].get("type")
        try:
            if kind == "integer":
                value = int(value)
            elif kind == "number":
                value = float(value)
            elif kind == "boolean":
                value = value if isinstance(value, bool) else str(value).strip().lower() in ("true", "1", "yes")
            elif kind == "object":
                value = json.loads(value) if isinstance(value, str) else value
                if not isinstance(value, dict):
                    raise TypeError
            elif kind == "array":
                if isinstance(value, str):
                    value = json.loads(value) if value.strip().startswith("[") else [v.strip() for v in value.split(",") if v.strip()]
                if not isinstance(value, list):
                    raise TypeError
                if spec["schema"].get("items", {}).get("type", "string") == "string":
                    value = [str(v) for v in value]
            else:
                value = value if isinstance(value, str) else json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ToolArgumentError(f"Argument '{public}' should be {kind}") from exc
        if isinstance(value, str) and len(value) > 20_000:
            raise ToolArgumentError(f"Argument '{public}' is too long")
        out[spec["py_name"]] = value
    return out


def canonical_arguments(args: dict[str, Any] | None) -> str:
    """ToolConfirmation.CanonicalArguments: key-sorted key=value pairs joined with '&'."""
    if not args:
        return ""
    return "&".join(f"{k}={args[k]}" for k in sorted(args, key=str.lower))
