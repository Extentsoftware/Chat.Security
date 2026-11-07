"""GeneralPlugin, LookupPlugin, ObservationsPlugin and ScoutSessionsPlugin."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

from .. import db
from ..executor import ToolContext
from ..registry import tool
from .common import farm_today, findings, new_id, parse_farm_date, utc_now

# --- GeneralPlugin -----------------------------------------------------------------------

@tool("GeneralPlugin", "Get the current date and time in UTC, plus today's farm calendar date (Africa/Harare).")
def GetDateAndTime(ctx: ToolContext):
    return {"utc": datetime.now(timezone.utc).isoformat(), "farmDate": farm_today().isoformat(),
            "farmTimeZone": "Africa/Harare"}


# --- LookupPlugin ------------------------------------------------------------------------

@tool("LookupPlugin", "Get list of lookup groups")
def GetLookupGroups(ctx: ToolContext):
    return db.rows("SELECT id, name FROM lookup_groups WHERE tenant_id = ? ORDER BY name", (ctx.tenant_id,))


@tool("LookupPlugin", "Given the id of a group, return a list of all subgroups within that group")
def GetLookupSubGroups(ctx: ToolContext, groupId: Annotated[str, "Lookup group id"]):
    return db.rows("SELECT id, name FROM lookup_sub_groups WHERE tenant_id = ? AND group_id = ? ORDER BY name",
                   (ctx.tenant_id, groupId))


@tool("LookupPlugin", "Given the id of a group, return a list of items in group, which includes all subgroups")
def GetLookupItems(ctx: ToolContext, groupId: Annotated[str, "Lookup group id"]):
    return db.rows("""SELECT i.id, i.name, i.description, s.name AS subGroup FROM lookup_items i
                      LEFT JOIN lookup_sub_groups s ON s.id = i.sub_group_id
                      WHERE i.tenant_id = ? AND i.group_id = ? ORDER BY s.name, i.name""", (ctx.tenant_id, groupId))


@tool("LookupPlugin", "Given the ids of subgroups, return a list of items in those subgroups")
def GetLookupItemsInSubGroups(ctx: ToolContext, subGroupIds: Annotated[list[str], "Subgroup ids"]):
    if not subGroupIds:
        return []
    marks = ",".join("?" * len(subGroupIds))
    return db.rows(f"SELECT id, name, description, sub_group_id AS subGroupId FROM lookup_items "
                   f"WHERE tenant_id = ? AND sub_group_id IN ({marks}) ORDER BY name", [ctx.tenant_id, *subGroupIds])


@tool("LookupPlugin", "Get farm locations/sections. Returns numeric Id and Name (section codes such as B1-S1, B2-S6), "
      "area and centroid. Use Id values with CreateActivity farmSectionIds.")
def GetLocations(ctx: ToolContext):
    return db.rows("""SELECT id AS Id, code AS Name, area_m2 AS AreaM2, centroid_lat AS Latitude, centroid_lng AS Longitude
                      FROM farm_sections WHERE tenant_id = ? ORDER BY code""", (ctx.tenant_id,))


# --- ObservationsPlugin ------------------------------------------------------------------

@tool("ObservationsPlugin", "Get list of observation types with their data point codes")
def GetObservationTypes(ctx: ToolContext):
    types = db.rows("SELECT id, name, description FROM observation_types WHERE is_active = 1 ORDER BY sort_order, name")
    for t in types:
        t["dataPoints"] = db.rows("""SELECT code, label, data_type AS dataType, is_required AS isRequired
                                     FROM observation_type_data_points WHERE observation_type_id = ?
                                     ORDER BY sort_order""", (t["id"],))
    return types


@tool("ObservationsPlugin",
      "Get observations. from/to filter the event timestamp (when it happened), not createdAt. "
      "Optionally filter by observation type and farm section. Most recent first.")
def GetObservations(ctx: ToolContext,
                    from_: Annotated[str | None, "Optional event-date from, ISO 8601 e.g. 2026-08-01"] = None,
                    to: Annotated[str | None, "Optional event-date to, ISO 8601 e.g. 2026-08-25"] = None,
                    observationType: Annotated[str | None, "Optional observation type, e.g. Weather. Case-insensitive."] = None,
                    farmSection: Annotated[str | None, "Optional farm section name, e.g. B2-S5"] = None,
                    take: Annotated[int, "Max rows (default 50, max 200)"] = 50):
    sql = ["""SELECT o.id, t.name AS type, o.summary, o.notes, o.severity, o.timestamp, o.farm_location_id AS section,
                     o.tree_line_number AS treeLine, o.tree_number AS tree, o.created_by AS createdBy
              FROM observations o LEFT JOIN observation_types t ON t.id = o.observation_type_id
              WHERE o.tenant_id = ?"""]
    params: list = [ctx.tenant_id]
    if (d := parse_farm_date(from_)):
        sql.append("AND substr(o.timestamp,1,10) >= ?"); params.append(d.isoformat())
    if (d := parse_farm_date(to)):
        sql.append("AND substr(o.timestamp,1,10) <= ?"); params.append(d.isoformat())
    if observationType:
        sql.append("AND lower(t.name) = lower(?)"); params.append(observationType.strip())
    if farmSection:
        sql.append("AND lower(o.farm_location_id) = lower(?)"); params.append(farmSection.strip())
    sql.append("ORDER BY o.timestamp DESC LIMIT ?"); params.append(max(1, min(take, 200)))
    result = db.rows(" ".join(sql), params)
    for r in result:
        r["data"] = {m["code"]: m["value"] for m in db.rows(
            """SELECT dp.code, m.value FROM observation_metadata m
               JOIN observation_type_data_points dp ON dp.id = m.data_point_id WHERE m.observation_id = ?""", (r["id"],))}
    return {"totalReturned": len(result), "observations": result}


@tool("ObservationsPlugin",
      "Latest observation date per farm section and observation type. Use to see what has not been looked at recently.")
def GetLatestObservationDates(ctx: ToolContext):
    return db.rows("""SELECT o.farm_location_id AS section, t.name AS type, max(substr(o.timestamp,1,10)) AS latest
                      FROM observations o LEFT JOIN observation_types t ON t.id = o.observation_type_id
                      WHERE o.tenant_id = ? GROUP BY o.farm_location_id, t.name ORDER BY section, type""", (ctx.tenant_id,))


@tool("ObservationsPlugin",
      "Record a new observation of a given type (e.g. 'Weather'). First call GetObservationTypes to discover the type's "
      "data point codes, then pass values as a JSON object mapping code -> value in dataJson, "
      "e.g. {\"temperature\":\"24.5\",\"humidity\":\"60\"}.")
def CreateObservation(ctx: ToolContext,
                      observationType: Annotated[str, "Observation type name, e.g. 'Weather'"],
                      summary: Annotated[str, "Short human-readable summary"],
                      dataJson: Annotated[str | None, "Optional JSON object mapping data point codes to values"] = None,
                      farmLocationId: Annotated[str | None, "Optional farm section code, e.g. B2-S5"] = None,
                      notes: Annotated[str | None, "Optional free-text notes"] = None,
                      severity: Annotated[str | None, "Information, Warning, or Fail (default Information)"] = None,
                      latitude: Annotated[float | None, "Optional latitude"] = None,
                      longitude: Annotated[float | None, "Optional longitude"] = None):
    otype = db.row("SELECT id, name FROM observation_types WHERE lower(name) = lower(?)", (observationType.strip(),))
    if otype is None:
        names = [r["name"] for r in db.rows("SELECT name FROM observation_types WHERE is_active = 1")]
        return f"Error: Unknown observation type '{observationType}'. Known types: {', '.join(names)}"
    sev = (severity or "Information").strip().capitalize()
    if sev not in ("Information", "Warning", "Fail"):
        return "Error: severity must be Information, Warning, or Fail."
    if farmLocationId and not db.scalar("SELECT 1 FROM farm_sections WHERE tenant_id = ? AND lower(code) = lower(?)",
                                        (ctx.tenant_id, farmLocationId.strip())):
        return f"Error: farm section '{farmLocationId}' does not exist on this farm."
    data = {}
    if dataJson:
        try:
            data = json.loads(dataJson)
            assert isinstance(data, dict)
        except (json.JSONDecodeError, AssertionError):
            return "Error: dataJson must be a JSON object mapping data point codes to values."
    points = {r["code"]: r["id"] for r in db.rows(
        "SELECT id, code FROM observation_type_data_points WHERE observation_type_id = ?", (otype["id"],))}
    bad = [k for k in data if k not in points]
    if bad:
        return f"Error: unknown data point code(s) {bad}. Valid: {sorted(points)}"
    oid, now = new_id(), utc_now()
    with db.write() as conn:
        conn.execute("""INSERT INTO observations (id, tenant_id, observation_type_id, summary, notes, severity, timestamp,
                        farm_location_id, latitude, longitude, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (oid, ctx.tenant_id, otype["id"], summary[:300], notes, sev, now, farmLocationId,
                      latitude, longitude, ctx.actor, now))
        for code, value in data.items():
            conn.execute("INSERT INTO observation_metadata (id, observation_id, data_point_id, value) VALUES (?,?,?,?)",
                         (new_id(), oid, points[code], str(value)))
    return {"created": True, "id": oid, "type": otype["name"], "summary": summary, "severity": sev}


# --- ScoutSessionsPlugin -----------------------------------------------------------------

def _orchard_summary(raw: str | None) -> str:
    try:
        checks = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return "All pass"
    issues = [f"{k} {v}" for k, v in checks.items() if str(v).lower() not in ("pass", "")]
    return " · ".join(issues) if issues else "All pass"


def _tree_report(t: dict) -> dict:
    pests, diseases, bens = (findings(t["pest_findings_json"]), findings(t["disease_findings_json"]),
                             findings(t["beneficial_findings_json"]))
    lat, lng = t["latitude"], t["longitude"]
    has_gps = lat is not None and lng is not None and (abs(lat) >= 0.001 or abs(lng) >= 0.001)
    return {"id": t["id"], "treeLineNumber": t["tree_line_number"], "treeNumber": t["tree_number"],
            "hasGps": has_gps, "latitude": lat if has_gps else None, "longitude": lng if has_gps else None,
            "plantHealth": t["plant_health"], "notes": t["notes"],
            "nothingFound": bool(t["nothing_found"]) and not (pests or diseases or bens),
            "pests": pests, "diseases": diseases, "beneficials": bens, "photoCount": t["photo_count"]}


@tool("ScoutSessionsPlugin",
      "List scout sessions (orchard walks). Returns session metadata only, no per-tree findings. "
      "Then call GetScoutSession or GetScoutTree for reports. Dates are Africa/Harare farm calendar days (yyyy-MM-dd). "
      "Omit status to include Draft and Submitted.")
def GetScoutSessions(ctx: ToolContext,
                     from_: Annotated[str | None, "Optional farm date to search from, yyyy-MM-dd"] = None,
                     to: Annotated[str | None, "Optional farm date to search to, yyyy-MM-dd"] = None,
                     section: Annotated[str | None, "Optional section code, e.g. B2-S4"] = None,
                     status: Annotated[str | None, "Optional status: Draft or Submitted"] = None,
                     take: Annotated[int, "Max sessions to return (default 50, max 100)"] = 50):
    where, params = ["s.tenant_id = ?"], [ctx.tenant_id]
    if (d := parse_farm_date(from_)):
        where.append("s.scout_date >= ?"); params.append(d.isoformat())
    if (d := parse_farm_date(to)):
        where.append("s.scout_date <= ?"); params.append(d.isoformat())
    if section:
        where.append("(lower(s.section_code) = lower(?) OR lower(s.farm_location_id) = lower(?))")
        params += [section.strip(), section.strip()]
    if status:
        where.append("lower(s.status) = lower(?)"); params.append(status.strip())
    clause = " AND ".join(where)
    total = db.scalar(f"SELECT count(*) FROM scout_sessions s WHERE {clause}", params)
    sessions = db.rows(f"""SELECT s.id, s.scout_date AS scoutDate, s.section_code AS sectionCode, s.status,
                                  s.created_by AS scout, s.phenology_stage AS phenologyStage, s.notes,
                                  (SELECT count(*) FROM scout_session_trees t WHERE t.scout_session_id = s.id) AS treeCount
                           FROM scout_sessions s WHERE {clause}
                           ORDER BY s.scout_date DESC, s.created_at DESC LIMIT ?""", [*params, max(1, min(take, 100))])
    return {"totalMatching": total, "totalReturned": len(sessions), "sessions": sessions}


@tool("ScoutSessionsPlugin",
      "Get one scout session and its tree reports: line/tree, GPS if captured, plant health, "
      "pest/disease/beneficial findings and photo count. Use after GetScoutSessions.")
def GetScoutSession(ctx: ToolContext, sessionId: Annotated[str, "Scout session id from GetScoutSessions"]):
    s = db.row("SELECT * FROM scout_sessions WHERE id = ? AND tenant_id = ?", (sessionId, ctx.tenant_id))
    if s is None:
        return {"found": False, "error": f"Scout session '{sessionId}' not found."}
    trees = db.rows("SELECT * FROM scout_session_trees WHERE scout_session_id = ? ORDER BY sort_order", (s["id"],))
    return {"found": True, "id": s["id"], "scoutDate": s["scout_date"], "sectionCode": s["section_code"],
            "status": s["status"], "scout": s["created_by"], "phenologyStage": s["phenology_stage"],
            "notes": s["notes"], "orchardChecksSummary": _orchard_summary(s["orchard_checks_json"]),
            "trees": [_tree_report(t) for t in trees]}


@tool("ScoutSessionsPlugin", "Get one tree report plus its session section and farm date. "
      "Use when you already have a tree id from GetScoutSession.")
def GetScoutTree(ctx: ToolContext, treeId: Annotated[str, "Scout session tree id"]):
    t = db.row("""SELECT t.*, s.scout_date, s.section_code, s.created_by FROM scout_session_trees t
                  JOIN scout_sessions s ON s.id = t.scout_session_id WHERE t.id = ? AND s.tenant_id = ?""",
               (treeId, ctx.tenant_id))
    if t is None:
        return {"found": False, "error": f"Scout tree '{treeId}' not found."}
    return {"found": True, **_tree_report(t), "sessionId": t["scout_session_id"], "scoutDate": t["scout_date"],
            "sectionCode": t["section_code"], "scout": t["created_by"]}


@tool("ScoutSessionsPlugin", "Orchard scout freshness: section codes oldest first. Band Red = never or >10 days, "
      "Orange >5 days, Green otherwise. Use this to pick exactly two sections for daily scouting.")
def GetScoutSectionAges(ctx: ToolContext):
    today = farm_today()
    last = {r["code"].lower(): r["last"] for r in db.rows(
        "SELECT section_code AS code, max(scout_date) AS last FROM scout_sessions WHERE tenant_id = ? "
        "AND section_code IS NOT NULL GROUP BY lower(section_code)", (ctx.tenant_id,))}
    out = []
    for f in db.rows("SELECT code FROM farm_sections WHERE tenant_id = ? AND is_orchard = 1", (ctx.tenant_id,)):
        seen = last.get(f["code"].lower())
        days = (today - parse_farm_date(seen)).days if seen else None
        band = "Red" if days is None or days > 10 else "Orange" if days > 5 else "Green"
        out.append({"sectionCode": f["code"], "daysSince": days,
                    "label": "never" if days is None else f"{days}d", "band": band})
    return sorted(out, key=lambda r: (-(r["daysSince"] if r["daysSince"] is not None else 10_000), r["sectionCode"]))


@tool("ScoutSessionsPlugin", "Pest and disease pressure per section over a date range, summed from scout tree "
      "reports: trees scouted, trees with each finding, total counts. Good for trends and heatmaps.")
def GetScoutPressure(ctx: ToolContext,
                     from_: Annotated[str | None, "Farm date from, yyyy-MM-dd (default 30 days ago)"] = None,
                     to: Annotated[str | None, "Farm date to, yyyy-MM-dd (default today)"] = None):
    start = parse_farm_date(from_) or (farm_today() - timedelta(days=30))
    end = parse_farm_date(to) or farm_today()
    trees = db.rows("""SELECT s.section_code, t.pest_findings_json, t.disease_findings_json FROM scout_session_trees t
                       JOIN scout_sessions s ON s.id = t.scout_session_id
                       WHERE s.tenant_id = ? AND s.scout_date BETWEEN ? AND ?""",
                    (ctx.tenant_id, start.isoformat(), end.isoformat()))
    sections: dict[str, dict] = {}
    for t in trees:
        sec = sections.setdefault(t["section_code"], {"section": t["section_code"], "treesScouted": 0, "findings": {}})
        sec["treesScouted"] += 1
        for f in findings(t["pest_findings_json"]) + findings(t["disease_findings_json"]):
            if f["count"] <= 0:
                continue
            agg = sec["findings"].setdefault(f["name"], {"treesAffected": 0, "totalCount": 0})
            agg["treesAffected"] += 1
            agg["totalCount"] += f["count"]
    for sec in sections.values():
        for agg in sec["findings"].values():
            agg["incidencePct"] = round(100 * agg["treesAffected"] / sec["treesScouted"], 1)
    return {"from": start.isoformat(), "to": end.isoformat(), "sections": sorted(sections.values(), key=lambda s: s["section"])}
