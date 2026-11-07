"""ActivitiesPlugin (+ SprayPurchase), ReportsPlugin and TasksPlugin."""
from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Annotated

from .. import db
from ..executor import ToolContext
from ..registry import tool
from ..security import Perm
from .common import farm_today, new_id, parse_farm_date, section_names, utc_now, validate_section_ids

AI_BOT = "AI Bot"
TYPES = ["Apply", "Clearing", "Construction", "Fireguard", "Groundwork", "Harvesting", "Irrigation", "Maintenance",
         "Mowing", "Mulching", "Nursery", "Other", "Pegging", "Planting", "Pruning", "Purchase", "Scouting",
         "Security", "Slashing", "Spraying", "Weeding"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
STATES = ["Proposed", "Planned", "InProgress", "OnHold", "Complete", "Discarded"]


def _event(conn, activity_id: str, ctx: ToolContext, from_state: str | None, to_state: str, note: str | None = None):
    if ctx.state.tainted:
        # No person can confirm on the unattended calendar run, so its proposals are allowed but marked,
        # and they still need a manager to authorise them.
        note = (note + " " if note else "") + f"[made while the AI context held untrusted content from {', '.join(ctx.state.tainted[:4])}]"
    conn.execute("INSERT INTO activity_events (activity_id, at, actor, from_state, to_state, note) VALUES (?,?,?,?,?,?)",
                 (activity_id, utc_now(), f"{ctx.actor} via AI ({ctx.state.channel})", from_state, to_state, note))


def _load(ctx: ToolContext, activity_id: str) -> dict | None:
    return db.row("SELECT * FROM activities WHERE id = ? AND tenant_id = ?", (activity_id.strip(), ctx.tenant_id))


def _row(ctx: ToolContext, a: dict) -> dict:
    details = json.loads(a["details_json"]) if a["details_json"] else {}
    out = {"activityId": a["id"], "type": a["activity_type"], "state": a["state"], "title": a["title"],
           "priority": a["priority"], "reason": a["reason"], "plannedStart": a["planned_start"],
           "sections": section_names(ctx.tenant_id, a["farm_section_ids"]), "farmSectionIds": a["farm_section_ids"],
           "team": a["team"], "createdBy": a["created_by"], "createdAt": a["created_at"]}
    if a["activity_type"] == "Apply" and details.get("chemicals"):
        out["chemicals"] = [c.get("name") or c.get("chemicalId") for c in details["chemicals"]]
    if details:
        out["details"] = details
    return out


def _parse_details(details_json: str | None) -> tuple[str | None, str | None]:
    if not details_json:
        return None, None
    try:
        parsed = json.loads(details_json)
    except json.JSONDecodeError:
        return None, "Error: detailsJson must be a JSON object."
    if not isinstance(parsed, dict):
        return None, "Error: detailsJson must be a JSON object."
    for chem in parsed.get("chemicals", []) or []:
        cid = chem.get("chemicalId")
        if cid:
            found = db.row("SELECT name FROM chemicals WHERE id = ?", (cid,))
            if found is None:
                return None, f"Error: chemicalId '{cid}' not found. Use ViewChemical to get ids."
            chem.setdefault("name", found["name"])
    return json.dumps(parsed), None


@tool("ActivitiesPlugin",
      "Create a new farm activity. It is always created in the Proposed state for a manager to authorise; you cannot "
      "set InProgress. For Scouting, put every chosen section on ONE activity via farmSectionIds (comma-separated numeric "
      "ids from GetLocations). For Apply, put the tank mix in detailsJson {\"method\":\"Boom\",\"chemicals\":[{\"chemicalId\":\"…\",\"rate\":…,\"rateUnit\":\"ml/100L\"}]}.")
def CreateActivity(ctx: ToolContext,
                   activityType: Annotated[str, "Activity type: " + ", ".join(TYPES)],
                   title: Annotated[str, "Short title"],
                   reason: Annotated[str | None, "Short reason/justification for proposing this activity"] = None,
                   farmSectionIds: Annotated[str | None, "Optional comma-separated numeric farm section ids, e.g. '1,4'"] = None,
                   team: Annotated[str | None, "Optional team name, e.g. Scout or Operations"] = None,
                   plannedStart: Annotated[str | None, "Optional planned start farm date yyyy-MM-dd"] = None,
                   priority: Annotated[str | None, "Low, Medium, High, or Critical. Defaults to Medium."] = None,
                   estimatedTeamSize: Annotated[int | None, "Optional estimated people on the team"] = None,
                   detailsJson: Annotated[str | None, "Optional type-specific details as a JSON object"] = None):
    atype = next((t for t in TYPES if t.lower() == activityType.strip().lower()), None)
    if atype is None:
        atype = "Scouting" if activityType.strip().lower() == "scout" else None
    if atype is None:
        return f"Error: unknown activity type '{activityType}'. Use one of: {', '.join(TYPES)}"
    prio = next((p for p in PRIORITIES if p.lower() == (priority or "Medium").strip().lower()), None)
    if prio is None:
        return "Error: priority must be Low, Medium, High or Critical."
    ids = validate_section_ids(ctx.tenant_id, farmSectionIds)
    start = parse_farm_date(plannedStart)
    details, err = _parse_details(detailsJson)
    if err:
        return err
    aid, now = new_id(), utc_now()
    with db.write() as conn:
        conn.execute("""INSERT INTO activities (id, tenant_id, activity_type, state, title, reason, priority, farm_section_ids,
                        details_json, planned_start, team, estimated_team_size, created_by, created_at, updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (aid, ctx.tenant_id, atype, "Proposed", title[:200], reason, prio, ids, details,
                      start.isoformat() if start else None, team, estimatedTeamSize, AI_BOT, now, now))
        _event(conn, aid, ctx, None, "Proposed", reason)
    return {"created": True, "activityId": aid, "state": "Proposed", "type": atype,
            "sections": section_names(ctx.tenant_id, ids), "message": "Proposed for a manager to authorise."}


@tool("ActivitiesPlugin",
      "Edit a Proposed or Planned activity you previously created (CreatedBy AI Bot). Prefer this over Discard+Create. "
      "Call GetActivities first and pass activityId. You cannot edit InProgress, Complete, or human-created activities.")
def EditActivity(ctx: ToolContext,
                 activityId: Annotated[str, "activityId from GetActivities (GUID)"],
                 reason: Annotated[str | None, "Updated reason"] = None,
                 farmSectionIds: Annotated[str | None, "Optional comma-separated numeric farm section ids"] = None,
                 plannedStart: Annotated[str | None, "Optional planned start yyyy-MM-dd"] = None,
                 priority: Annotated[str | None, "Optional priority"] = None,
                 team: Annotated[str | None, "Optional team"] = None,
                 detailsJson: Annotated[str | None, "Optional replacement details JSON"] = None):
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["created_by"] != AI_BOT:
        return "Error: this activity was created by a person; only AI-created proposals can be edited by the assistant."
    if a["state"] not in ("Proposed", "Planned"):
        return f"Error: cannot edit an activity in state {a['state']}."
    updates: dict = {}
    if reason is not None:
        updates["reason"] = reason
    if farmSectionIds is not None:
        updates["farm_section_ids"] = validate_section_ids(ctx.tenant_id, farmSectionIds)
    if plannedStart is not None:
        updates["planned_start"] = parse_farm_date(plannedStart).isoformat()
    if priority is not None:
        prio = next((p for p in PRIORITIES if p.lower() == priority.strip().lower()), None)
        if prio is None:
            return "Error: priority must be Low, Medium, High or Critical."
        updates["priority"] = prio
    if team is not None:
        updates["team"] = team
    if detailsJson is not None:
        details, err = _parse_details(detailsJson)
        if err:
            return err
        updates["details_json"] = details
    if not updates:
        return "Error: nothing to change."
    updates["updated_at"] = utc_now()
    with db.write() as conn:
        conn.execute(f"UPDATE activities SET {', '.join(f'{k} = ?' for k in updates)} WHERE id = ?",
                     [*updates.values(), a["id"]])
        _event(conn, a["id"], ctx, a["state"], a["state"], "edited: " + ", ".join(k for k in updates if k != "updated_at"))
    return {"edited": True, "activity": _row(ctx, _load(ctx, a["id"]))}


@tool("ActivitiesPlugin", "Discard a Proposed or Planned activity you previously created so it leaves the queue. "
      "You cannot discard InProgress, Complete, or human-created activities.")
def DiscardActivity(ctx: ToolContext, activityId: Annotated[str, "activityId from GetActivities (GUID)"],
                    reason: Annotated[str | None, "Short reason this proposal is withdrawn"] = None):
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["created_by"] != AI_BOT or a["state"] not in ("Proposed", "Planned"):
        return "Error: only AI-created Proposed or Planned activities can be discarded by the assistant."
    return _transition(ctx, a, "Discarded", reason)


def _transition(ctx: ToolContext, a: dict, to_state: str, note: str | None = None) -> dict:
    now = utc_now()
    with db.write() as conn:
        conn.execute("UPDATE activities SET state = ?, updated_at = ?, completed_at = ? WHERE id = ?",
                     (to_state, now, now if to_state == "Complete" else a["completed_at"], a["id"]))
        _event(conn, a["id"], ctx, a["state"], to_state, note)
    return {"activityId": a["id"], "from": a["state"], "to": to_state, "title": a["title"]}


@tool("ActivitiesPlugin", "Mark a farm activity Complete after you confirm with the manager first.")
def CompleteActivity(ctx: ToolContext, activityId: Annotated[str, "activityId from GetActivities (GUID)"]):
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["state"] not in ("Planned", "InProgress", "OnHold"):
        return f"Error: cannot complete an activity in state {a['state']}."
    return _transition(ctx, a, "Complete")


@tool("ActivitiesPlugin", "Put a farm activity OnHold after you confirm with the manager first.")
def HoldActivity(ctx: ToolContext, activityId: Annotated[str, "activityId from GetActivities (GUID)"]):
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["state"] not in ("Planned", "InProgress"):
        return f"Error: cannot hold an activity in state {a['state']}."
    return _transition(ctx, a, "OnHold")


@tool("ActivitiesPlugin", "Authorise a Proposed farm activity (move to Planned) after you confirm with the manager first.")
def AuthoriseActivity(ctx: ToolContext, activityId: Annotated[str, "activityId from GetActivities (GUID)"]):
    if not ctx.principal.has(Perm.AUTHORISE_ACTIVITIES):
        return f"Error: your role '{ctx.principal.rolename}' does not hold the authorise-activities permission (a-act-auth)."
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["state"] != "Proposed":
        return f"Error: only Proposed activities can be authorised (this one is {a['state']})."
    return _transition(ctx, a, "Planned", f"authorised by {ctx.principal.display_name}")


@tool("ActivitiesPlugin", "Start a farm activity (InProgress) after you confirm with the manager first. "
      "Apply activities need a tank mix (chemicals) in their details before they can start.")
def StartActivity(ctx: ToolContext, activityId: Annotated[str, "activityId from GetActivities (GUID)"]):
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["state"] != "Planned":
        return f"Error: only Planned activities can be started (this one is {a['state']})."
    details = json.loads(a["details_json"]) if a["details_json"] else {}
    if a["activity_type"] == "Apply" and not details.get("chemicals"):
        return "Error: execution validation failed - Apply needs chemicals in details. Call EditActivity first."
    return _transition(ctx, a, "InProgress")


@tool("ActivitiesPlugin", "Record Assembly actuals on an InProgress activity after you confirm with the manager first. "
      "Headcount is permanentStaffCount plus temporaryWorkerCount.")
def SetActivityActuals(ctx: ToolContext, activityId: Annotated[str, "activityId from GetActivities (GUID)"],
                       workDate: Annotated[str | None, "Farm date yyyy-MM-dd (default today)"] = None,
                       permanentStaffCount: Annotated[int | None, "Permanent staff count"] = None,
                       temporaryWorkerCount: Annotated[int | None, "Temporary worker count"] = None,
                       supervisor: Annotated[str | None, "Supervisor name"] = None,
                       equipmentUsed: Annotated[str | None, "Equipment used, e.g. Jacto, Misty, Formend"] = None,
                       notes: Annotated[str | None, "Optional notes"] = None):
    a = _load(ctx, activityId)
    if a is None:
        return f"Error: activity '{activityId}' not found."
    if a["state"] != "InProgress":
        return "Error: actuals can only be recorded on an InProgress activity."
    for n in (permanentStaffCount, temporaryWorkerCount):
        if n is not None and not 0 <= n <= 500:
            return "Error: staff counts must be between 0 and 500."
    day = (parse_farm_date(workDate) or farm_today()).isoformat()
    with db.write() as conn:
        conn.execute("""INSERT INTO activity_actuals (id, activity_id, work_date, permanent_staff, temporary_workers,
                        supervisor, equipment, notes, recorded_by, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (new_id(), a["id"], day, permanentStaffCount, temporaryWorkerCount, supervisor, equipmentUsed,
                      notes, ctx.actor, utc_now()))
    return {"recorded": True, "activityId": a["id"], "workDate": day,
            "headcount": (permanentStaffCount or 0) + (temporaryWorkerCount or 0)}


@tool("ActivitiesPlugin", "Get farm activities, optionally filtered by state (Proposed, Planned, InProgress, OnHold, "
      "Complete, Discarded; combine with comma or plus) and activity type. Most recent first. Each row has activityId, "
      "sections (names such as B1-S1, say these to the manager) and farmSectionIds (numeric ids for tool arguments only).")
def GetActivities(ctx: ToolContext,
                  state: Annotated[str | None, "Optional state filter, e.g. 'Proposed+Planned'"] = None,
                  activityType: Annotated[str | None, "Optional activity type, e.g. Apply or Scouting"] = None,
                  pageSize: Annotated[int, "How many items to return (default 100)"] = 100):
    where, params = ["tenant_id = ?"], [ctx.tenant_id]
    if state:
        wanted = [s.strip().lower() for s in re.split(r"[,+]", state) if s.strip()]
        where.append(f"lower(state) IN ({','.join('?' * len(wanted))})"); params += wanted
    if activityType:
        t = "scouting" if activityType.strip().lower() == "scout" else activityType.strip().lower()
        where.append("lower(activity_type) = ?"); params.append(t)
    found = db.rows(f"SELECT * FROM activities WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT ?",
                    [*params, max(1, min(pageSize, 300))])
    return [_row(ctx, a) for a in found]


@tool("ActivitiesPlugin", "Reported Assembly actuals (manpower and equipment) for farm activities, filtered by date "
      "range and optional activity type.")
def GetActivityActuals(ctx: ToolContext, from_: Annotated[str | None, "Optional from date yyyy-MM-dd"] = None,
                       to: Annotated[str | None, "Optional to date yyyy-MM-dd"] = None,
                       activityType: Annotated[str | None, "Optional activity type"] = None):
    where, params = ["a.tenant_id = ?"], [ctx.tenant_id]
    if (d := parse_farm_date(from_)):
        where.append("x.work_date >= ?"); params.append(d.isoformat())
    if (d := parse_farm_date(to)):
        where.append("x.work_date <= ?"); params.append(d.isoformat())
    if activityType:
        where.append("lower(a.activity_type) = lower(?)"); params.append(activityType.strip())
    return db.rows(f"""SELECT a.id AS activityId, a.title, a.activity_type AS type, x.work_date AS workDate,
                              x.permanent_staff AS permanentStaff, x.temporary_workers AS temporaryWorkers,
                              x.supervisor, x.equipment, x.notes FROM activity_actuals x
                       JOIN activities a ON a.id = x.activity_id WHERE {' AND '.join(where)}
                       ORDER BY x.work_date DESC LIMIT 200""", params)


@tool("ActivitiesPlugin",
      "Create or update ONE consolidated High-priority Proposed Purchase task for the Director team. Call after reading "
      "'A. Immediate purchase' in a freshly generated Pest and Disease Spray Analysis report.")
def ProposeSprayPurchaseTask(ctx: ToolContext,
                             purchaseList: Annotated[str, "Concise procurement list: sections, pests, options with totals"],
                             reportId: Annotated[str, "ID returned by GeneratePestDiseaseSprayAnalysis"],
                             analysisPurchaseRequired: Annotated[bool, "True only when your analysis needs purchases beyond the report"] = False):
    report = db.row("""SELECT r.* FROM reports r JOIN report_groups g ON g.id = r.group_id
                       WHERE r.id = ? AND g.tenant_id = ?""", (reportId, ctx.tenant_id))
    if report is None:
        return "Error: reportId not found. Call GeneratePestDiseaseSprayAnalysis first."
    section = report["content_md"].split("## A. Immediate purchase", 1)
    source = section[1].split("\n## ", 1)[0].strip() if len(section) > 1 else "(none)"
    details = json.dumps({"subTask": "Get quote", "purchaseList": purchaseList, "reportId": reportId,
                          "reportImmediatePurchase": source, "analysisPurchaseRequired": analysisPurchaseRequired})
    existing = db.row("""SELECT * FROM activities WHERE tenant_id = ? AND activity_type = 'Purchase' AND state = 'Proposed'
                         AND created_by = ? ORDER BY created_at DESC LIMIT 1""", (ctx.tenant_id, AI_BOT))
    now = utc_now()
    with db.write() as conn:
        if existing:
            conn.execute("UPDATE activities SET details_json = ?, reason = ?, updated_at = ? WHERE id = ?",
                         (details, "Spray chemical purchase from report " + report["title"], now, existing["id"]))
            _event(conn, existing["id"], ctx, "Proposed", "Proposed", "purchase list updated")
            return {"updated": True, "activityId": existing["id"]}
        aid = new_id()
        conn.execute("""INSERT INTO activities (id, tenant_id, activity_type, state, title, reason, priority, details_json,
                        team, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (aid, ctx.tenant_id, "Purchase", "Proposed", "Spray chemical purchase",
                      "Spray chemical purchase from report " + report["title"], "High", details, "Director", AI_BOT, now, now))
        _event(conn, aid, ctx, None, "Proposed", "purchase task proposed")
    return {"created": True, "activityId": aid, "state": "Proposed", "priority": "High"}


# --- ReportsPlugin -------------------------------------------------------------------------

SPRAY_GROUP = "Pest and Disease"
SPRAY_TITLE = "Pest and Disease Spray Analysis"
THRESHOLDS = {"stink bugs": 10, "mealybugs": 15, "thrips": 20, "nut borer": 5, "giant loopers": 10,
              "felted coccid": 15, "black citrus aphid": 20, "scales": 15}


@tool("ReportsPlugin", "Regenerate the Pest and Disease Spray Analysis report from live scouting (last 14 days), spray "
      "history, and the chemical table. Call this before GetReportContent when planning sprays. Returns the new report id.")
def GeneratePestDiseaseSprayAnalysis(ctx: ToolContext):
    from .farm_reads import GetScoutPressure
    pressure = GetScoutPressure(ctx, from_=(farm_today() - timedelta(days=14)).isoformat())
    lines = [f"# {SPRAY_TITLE}", f"Produced {farm_today().isoformat()} from scouting {pressure['from']} to {pressure['to']}.",
             "", "## Section pressure", "", "| Section | Trees | Finding | Trees affected | Incidence % | Threshold % | Action |",
             "|---|---|---|---|---|---|---|"]
    due: dict[str, list[str]] = {}
    for sec in pressure["sections"]:
        for name, agg in sorted(sec["findings"].items(), key=lambda kv: -kv[1]["incidencePct"]):
            limit = THRESHOLDS.get(name.lower(), 20)
            action = "SPRAY" if agg["incidencePct"] >= limit else "monitor"
            if action == "SPRAY":
                due.setdefault(name, []).append(sec["section"])
            lines.append(f"| {sec['section']} | {sec['treesScouted']} | {name} | {agg['treesAffected']} | "
                         f"{agg['incidencePct']} | {limit} | {action} |")
    lines += ["", "## Recommended products", ""]
    purchase = []
    for pest, secs in due.items():
        key = pest.lower().split()[0].rstrip("s")
        chems = db.rows("""SELECT name, type, notes, stock_on_hand, stock_unit FROM chemicals WHERE tenant_id = ?
                           AND is_active = 1 AND (lower(target) LIKE ? OR lower(description) LIKE ?) ORDER BY name LIMIT 3""",
                        (ctx.tenant_id, f"%{key}%", f"%{key}%"))
        names = ", ".join(f"{c['name']} ({c['notes'] or c['type']})" for c in chems) or "no product on file"
        lines.append(f"- **{pest}** in {', '.join(secs)}: {names}")
        for c in chems[:1]:
            if not c["stock_on_hand"]:
                purchase.append(f"- {c['name']} for {pest} ({', '.join(secs)}): stock {c['stock_on_hand'] or 0} {c['stock_unit'] or ''}")
    recent = db.rows("""SELECT title, state, planned_start FROM activities WHERE tenant_id = ? AND activity_type = 'Apply'
                        ORDER BY created_at DESC LIMIT 5""", (ctx.tenant_id,))
    lines += ["", "## A. Immediate purchase", "", *(purchase or ["- None: selected products are in stock."]),
              "", "## Recent spray activities", "", *([f"- {r['title']} ({r['state']}, {r['planned_start'] or 'unscheduled'})"
                                                         for r in recent] or ["- None recorded."])]
    content = "\n".join(lines)
    group = db.row("SELECT id FROM report_groups WHERE tenant_id = ? AND name = ?", (ctx.tenant_id, SPRAY_GROUP))
    rid, now = new_id(), utc_now()
    with db.write() as conn:
        if group is None:
            group = {"id": new_id()}
            conn.execute("INSERT INTO report_groups (id, tenant_id, name) VALUES (?,?,?)", (group["id"], ctx.tenant_id, SPRAY_GROUP))
        conn.execute("UPDATE reports SET is_active = 0 WHERE group_id = ? AND title = ?", (group["id"], SPRAY_TITLE))
        conn.execute("INSERT INTO reports (id, group_id, title, description, content_md, produced_at) VALUES (?,?,?,?,?,?)",
                     (rid, group["id"], SPRAY_TITLE, "Generated from live scouting", content, now))
    return {"reportId": rid, "title": SPRAY_TITLE, "produced": now, "sectionsDue": due}


@tool("ReportsPlugin", "Deprecated name for GeneratePestDiseaseSprayAnalysis. Same behaviour.")
def GeneratePestSprayAnalysis(ctx: ToolContext):
    return GeneratePestDiseaseSprayAnalysis(ctx)


@tool("ReportsPlugin", "Get all active report groups. Each group contains a collection of related reports.")
def GetReportGroups(ctx: ToolContext):
    return db.rows("""SELECT g.name, (SELECT count(*) FROM reports r WHERE r.group_id = g.id AND r.is_active = 1) AS reports
                      FROM report_groups g WHERE g.tenant_id = ? AND g.is_active = 1 ORDER BY g.name""", (ctx.tenant_id,))


@tool("ReportsPlugin", "Get active reports for a report group by group name. Returns titles, descriptions and dates, not content.")
def GetReports(ctx: ToolContext, groupName: Annotated[str, "Report group name"]):
    return db.rows("""SELECT r.id, r.title, r.description, r.produced_at AS produced FROM reports r
                      JOIN report_groups g ON g.id = r.group_id WHERE g.tenant_id = ? AND lower(g.name) = lower(?)
                      AND r.is_active = 1 ORDER BY r.produced_at DESC""", (ctx.tenant_id, groupName.strip()))


@tool("ReportsPlugin", "Get the markdown content of a specific report by its title. Use GetReports first. "
      "Set stripCharts=true to omit :::chart blocks.")
def GetReportContent(ctx: ToolContext, title: Annotated[str, "Report title"],
                     stripCharts: Annotated[bool, "Omit chart JSON blocks"] = False):
    r = db.row("""SELECT r.content_md FROM reports r JOIN report_groups g ON g.id = r.group_id
                  WHERE g.tenant_id = ? AND lower(r.title) = lower(?) AND r.is_active = 1
                  ORDER BY r.produced_at DESC LIMIT 1""", (ctx.tenant_id, title.strip()))
    if r is None:
        return f"Error: no active report titled '{title}'."
    text = r["content_md"]
    return re.sub(r":::chart.*?:::", "", text, flags=re.DOTALL) if stripCharts else text


# --- TasksPlugin -------------------------------------------------------------------------------

@tool("TasksPlugin", "Sprints (or boards) are kept in folders. Currently we have farm and purchasing.")
def GetSprintFolders(ctx: ToolContext):
    return [r["folder"] for r in db.rows("SELECT DISTINCT folder FROM boards WHERE tenant_id = ? ORDER BY folder", (ctx.tenant_id,))]


@tool("TasksPlugin", "Get a list of sprint boards, in start date descending order")
def GetSprints(ctx: ToolContext, pageSize: Annotated[int, "How many items to return"] = 26):
    return db.rows("SELECT id, folder, name, start_date AS startDate, end_date AS endDate FROM boards WHERE tenant_id = ? "
                   "ORDER BY start_date DESC LIMIT ?", (ctx.tenant_id, max(1, min(pageSize, 100))))


def _tasks(board_id: str) -> list[dict]:
    return db.rows("SELECT title, task_type AS type, status, assignee, start_date AS startDate, notes FROM board_tasks "
                   "WHERE board_id = ? ORDER BY start_date", (board_id,))


@tool("TasksPlugin", "Get tasks for this current sprint")
def GetTasksForThisSprint(ctx: ToolContext, folder: Annotated[str, "Folder: farm or purchasing"] = "farm"):
    today = farm_today().isoformat()
    b = db.row("SELECT * FROM boards WHERE tenant_id = ? AND lower(folder) = lower(?) AND start_date <= ? AND end_date >= ?",
               (ctx.tenant_id, folder, today, today))
    if b is None:
        return f"No sprint covers today in folder '{folder}'."
    return {"board": b["name"], "tasks": _tasks(b["id"])}


@tool("TasksPlugin", "Get board containing the most recent recorded task")
def GetLatestBoard(ctx: ToolContext):
    b = db.row("""SELECT b.* FROM boards b JOIN board_tasks t ON t.board_id = b.id WHERE b.tenant_id = ?
                  ORDER BY t.created_at DESC LIMIT 1""", (ctx.tenant_id,))
    return {"board": b["name"], "folder": b["folder"], "tasks": _tasks(b["id"])} if b else "No boards."


@tool("TasksPlugin", "Get all task types")
def GetAListOfTaskTypes(ctx: ToolContext):
    return [r["task_type"] for r in db.rows("""SELECT DISTINCT t.task_type FROM board_tasks t JOIN boards b ON b.id = t.board_id
                                               WHERE b.tenant_id = ? AND t.task_type IS NOT NULL ORDER BY 1""", (ctx.tenant_id,))]


@tool("TasksPlugin", "Get list of tasks ordered by start date descending, optionally filtered by created from/to and task type")
def GetTasks(ctx: ToolContext, from_: Annotated[str | None, "Optional created-from date yyyy-MM-dd"] = None,
             to: Annotated[str | None, "Optional created-to date yyyy-MM-dd"] = None,
             taskType: Annotated[str | None, "Optional task type name"] = None):
    where, params = ["b.tenant_id = ?"], [ctx.tenant_id]
    if (d := parse_farm_date(from_)):
        where.append("substr(t.created_at,1,10) >= ?"); params.append(d.isoformat())
    if (d := parse_farm_date(to)):
        where.append("substr(t.created_at,1,10) <= ?"); params.append(d.isoformat())
    if taskType:
        where.append("lower(t.task_type) = lower(?)"); params.append(taskType)
    return db.rows(f"""SELECT t.title, t.task_type AS type, t.status, t.assignee, t.start_date AS startDate, b.name AS board
                       FROM board_tasks t JOIN boards b ON b.id = t.board_id WHERE {' AND '.join(where)}
                       ORDER BY t.start_date DESC LIMIT 200""", params)
