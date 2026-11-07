from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from typing import Any

from ..config import FARM_TZ


def farm_today() -> date:
    return datetime.now(FARM_TZ).date()


def parse_farm_date(value: str | None) -> date | None:
    """ScoutSessionsPlugin.ParseFarmDate: yyyy-MM-dd or ISO 8601; raises on junk."""
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
        except ValueError as exc:
            raise ValueError(f"Invalid farm date '{value}'. Use yyyy-MM-dd, e.g. 2026-08-24.") from exc


def findings(raw: str | None) -> list[dict[str, Any]]:
    try:
        items = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return []
    return [{"name": i.get("name", ""), "count": int(i.get("count") or 0)} for i in items if i.get("name")]


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def section_names(tenant_id: str, ids_csv: str | None) -> list[str]:
    from .. import db
    ids = [i.strip() for i in (ids_csv or "").split(",") if i.strip()]
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    found = {str(r["id"]): r["code"] for r in db.rows(
        f"SELECT id, code FROM farm_sections WHERE tenant_id = ? AND id IN ({marks})", [tenant_id, *ids])}
    return [found.get(i, f"#{i}") for i in ids]


def validate_section_ids(tenant_id: str, ids_csv: str | None) -> str | None:
    """Return a normalised csv of ids that exist in this tenant, or raise."""
    from .. import db
    if not ids_csv:
        return None
    ids = [i.strip() for i in ids_csv.split(",") if i.strip()]
    for i in ids:
        if not i.isdigit():
            raise ValueError(f"farmSectionIds must be numeric ids from GetLocations, got '{i}'.")
        if not db.scalar("SELECT 1 FROM farm_sections WHERE tenant_id = ? AND id = ?", (tenant_id, int(i))):
            raise ValueError(f"Farm section id {i} does not exist on this farm.")
    return ",".join(ids)
