"""ChemicalPlugin, EquipmentPlugin, FuelPlugin, WeatherPlugin, UserInterfaceCommandPlugin, HarnessPlugin."""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Annotated

import httpx

from .. import db
from ..config import settings
from ..executor import ToolContext
from ..registry import tool
from .common import parse_farm_date

# --- ChemicalPlugin ----------------------------------------------------------------------

@tool("ChemicalPlugin", "View chemicals/products from the farm database (authoritative). Filter by name fragment and/or "
      "target pest/disease text. For spray planning prefer ONE broad call. Returns id, type, IRAC/FRAC, rates, PHI, stock.")
def ViewChemical(ctx: ToolContext, nameContains: Annotated[str | None, "Optional name fragment, e.g. 'Acephate'"] = None,
                 targetContains: Annotated[str | None, "Optional target pest/disease fragment, e.g. 'stink' or 'thrip'"] = None,
                 pageSize: Annotated[int, "How many rows (15-30 for planning)"] = 25):
    where, params = ["tenant_id = ?", "is_active = 1"], [ctx.tenant_id]
    if nameContains:
        where.append("lower(name) LIKE ?"); params.append(f"%{nameContains.strip().lower()}%")
    if targetContains:
        where.append("(lower(target) LIKE ? OR lower(description) LIKE ?)")
        params += [f"%{targetContains.strip().lower()}%"] * 2
    return db.rows(f"""SELECT id, name, type, notes AS modeOfAction, description, target, irac_code AS irac, frac_code AS frac,
                              min_rate_per_100l AS minRatePer100L, max_rate_per_100l AS maxRatePer100L, rate_unit AS rateUnit,
                              phi_days AS phiDays, stock_on_hand AS stockOnHand, stock_unit AS stockUnit, price, price_currency AS currency
                       FROM chemicals WHERE {' AND '.join(where)} ORDER BY name LIMIT ?""", [*params, max(1, min(pageSize, 100))])


@tool("ChemicalPlugin", "Check stock on hand for a chemical by name (or fragment). Returns the quantity and unit.")
def CheckChemicalStock(ctx: ToolContext, name: Annotated[str, "Chemical name or fragment"]):
    found = db.rows("SELECT name, stock_on_hand AS stockOnHand, stock_unit AS unit FROM chemicals WHERE tenant_id = ? "
                    "AND lower(name) LIKE ? ORDER BY name LIMIT 10", (ctx.tenant_id, f"%{name.strip().lower()}%"))
    if not found:
        return {"found": False, "note": f"No chemical matching '{name}'."}
    for f in found:
        f["note"] = "out of stock" if not f["stockOnHand"] else "in stock"
    return {"found": True, "items": found}


# --- EquipmentPlugin -------------------------------------------------------------------

@tool("EquipmentPlugin", "View farm equipment (tractors, sprayers, mowers, etc.) with status, running hours and service schedule.")
def ViewEquipment(ctx: ToolContext, nameContains: Annotated[str | None, "Optional name fragment"] = None,
                  status: Annotated[str | None, "Optional status, e.g. Operational or Broken"] = None):
    where, params = ["tenant_id = ?", "is_active = 1"], [ctx.tenant_id]
    if nameContains:
        where.append("lower(name) LIKE ?"); params.append(f"%{nameContains.lower()}%")
    if status:
        where.append("lower(status) = lower(?)"); params.append(status)
    items = db.rows(f"""SELECT id, name, equipment_type AS type, serial_number AS serial, location, status,
                               service_interval_hours AS serviceIntervalHours, current_hours AS currentHours,
                               last_service_hours AS lastServiceHours, last_service_date AS lastServiceDate, notes
                        FROM equipment WHERE {' AND '.join(where)} ORDER BY name""", params)
    for e in items:
        if e["serviceIntervalHours"] and e["currentHours"] is not None and e["lastServiceHours"] is not None:
            e["hoursUntilService"] = round(e["lastServiceHours"] + e["serviceIntervalHours"] - e["currentHours"], 1)
    return items


@tool("EquipmentPlugin", "View the service/maintenance log for a piece of equipment, found by name or fragment. Most recent first.")
def ViewVehicleLogs(ctx: ToolContext, equipmentName: Annotated[str, "Equipment name or fragment"]):
    return db.rows("""SELECT e.name AS equipment, l.service_type AS serviceType, l.description, l.performed_by AS performedBy,
                             l.service_date AS serviceDate, l.hours_at_service AS hours, l.cost, l.notes
                      FROM equipment_service_logs l JOIN equipment e ON e.id = l.equipment_id
                      WHERE e.tenant_id = ? AND lower(e.name) LIKE ? ORDER BY l.service_date DESC LIMIT 50""",
                   (ctx.tenant_id, f"%{equipmentName.strip().lower()}%"))


# --- FuelPlugin ------------------------------------------------------------------------------

def _on_hand(tank_id: str) -> float:
    total = 0.0
    for m in db.rows("SELECT kind, quantity_litres FROM fuel_movements WHERE fuel_tank_id = ?", (tank_id,)):
        total += m["quantity_litres"] if m["kind"] in ("Delivery", "AdjustUp") else -m["quantity_litres"]
    return round(total, 1)


@tool("FuelPlugin", "List fuel tanks with id, name, and on-hand litres from the farm database.")
def GetFuelTanks(ctx: ToolContext):
    tanks = db.rows("SELECT id, name, unit FROM fuel_tanks WHERE tenant_id = ? ORDER BY sort_order", (ctx.tenant_id,))
    for t in tanks:
        t["onHandLitres"] = _on_hand(t["id"])
    return tanks


@tool("FuelPlugin", "List fuel movements for diesel or petrol (newest first, max 100). Optional from/to as yyyy-MM-dd.")
def GetFuelMovements(ctx: ToolContext, fuel: Annotated[str, "Diesel or Petrol"] = "Diesel",
                     from_: Annotated[str | None, "Optional from date"] = None, to: Annotated[str | None, "Optional to date"] = None):
    where, params = ["t.tenant_id = ?", "lower(t.name) = lower(?)"], [ctx.tenant_id, fuel.strip()]
    if (d := parse_farm_date(from_)):
        where.append("m.occurred_on >= ?"); params.append(d.isoformat())
    if (d := parse_farm_date(to)):
        where.append("m.occurred_on <= ?"); params.append(d.isoformat())
    return db.rows(f"""SELECT m.occurred_on AS date, m.kind, m.quantity_litres AS litres, mc.name AS machine, m.notes, m.source
                       FROM fuel_movements m JOIN fuel_tanks t ON t.id = m.fuel_tank_id
                       LEFT JOIN fuel_machines mc ON mc.id = m.machine_id WHERE {' AND '.join(where)}
                       ORDER BY m.occurred_on DESC LIMIT 100""", params)


@tool("FuelPlugin", "List machines with name, description, tank name (Diesel/Petrol, null when it uses no fuel), meter flag and unit.")
def GetFuelMachines(ctx: ToolContext):
    return db.rows("""SELECT m.id, m.name, m.description, m.fuel_tank_id AS tankId, t.name AS tankName,
                             m.has_meter AS hasMeter, m.meter_unit AS meterUnit, m.is_active AS active
                      FROM fuel_machines m LEFT JOIN fuel_tanks t ON t.id = m.fuel_tank_id
                      WHERE m.tenant_id = ? ORDER BY m.name""", (ctx.tenant_id,))


@tool("FuelPlugin", "Monthly machine fuel usage by tank (diesel and petrol), on-hand, suggested buy, and a grouped-bar chart JSON.")
def GetFuelUsageMonthly(ctx: ToolContext):
    usage: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for m in db.rows("""SELECT t.name AS tank, substr(m.occurred_on,1,7) AS month, m.quantity_litres AS litres
                        FROM fuel_movements m JOIN fuel_tanks t ON t.id = m.fuel_tank_id
                        WHERE t.tenant_id = ? AND m.kind = 'Issue'""", (ctx.tenant_id,)):
        usage[m["month"]][m["tank"]] += m["litres"]
    months = sorted(usage)[-6:]
    tanks = GetFuelTanks(ctx)
    summary = []
    for t in tanks:
        recent = [usage[mo].get(t["name"], 0) for mo in months]
        avg = sum(recent) / len(recent) if recent else 0
        summary.append({"tank": t["name"], "onHandLitres": t["onHandLitres"], "avgMonthlyUseLitres": round(avg, 1),
                        "suggestedBuyLitres": max(0, round(avg * 1.2 - t["onHandLitres"]))})
    chart = {"type": "bar", "categories": months,
             "series": [{"name": t["name"], "data": [round(usage[mo].get(t["name"], 0), 1) for mo in months]} for t in tanks]}
    return {"summary": summary, "chart": chart}


# --- WeatherPlugin (Open-Meteo, no key needed) --------------------------------------------

def _tenant_point(ctx: ToolContext) -> tuple[float, float, str]:
    t = db.row("SELECT name, latitude, longitude FROM tenants WHERE id = ?", (ctx.tenant_id,)) or {}
    return t.get("latitude") or -17.83, t.get("longitude") or 31.05, t.get("name") or "farm"


@tool("WeatherPlugin", "Get the current weather for a location. Provide latitude+longitude, or omit both for the farm. "
      "Returns temperature, humidity, precipitation, wind. Use before recording a weather observation.")
def GetWeather(ctx: ToolContext, latitude: Annotated[float | None, "Latitude"] = None,
               longitude: Annotated[float | None, "Longitude"] = None):
    if latitude is None or longitude is None:
        latitude, longitude, _ = _tenant_point(ctx)
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return "Error: latitude/longitude out of range."
    if not settings.weather_online:
        return "Error: weather lookups are switched off (BONGO_WEATHER_ONLINE=0)."
    r = httpx.get("https://api.open-meteo.com/v1/forecast", timeout=15, params={
        "latitude": latitude, "longitude": longitude, "timezone": "Africa/Harare",
        "current": "temperature_2m,relative_humidity_2m,precipitation,wind_speed_10m,weather_code"})
    r.raise_for_status()
    cur = r.json().get("current", {})
    return {"latitude": latitude, "longitude": longitude, "time": cur.get("time"),
            "temperatureC": cur.get("temperature_2m"), "humidityPct": cur.get("relative_humidity_2m"),
            "precipitationMm": cur.get("precipitation"), "windKmh": cur.get("wind_speed_10m"),
            "weatherCode": cur.get("weather_code"), "source": "open-meteo.com"}


@tool("WeatherPlugin", "Get the farm weather brief: yesterday's rainfall, today's forecast high/low, rain chance, and "
      "whether the next 24h suit spraying (wind < 15 km/h, no rain).")
def GetFarmWeatherBrief(ctx: ToolContext):
    lat, lng, name = _tenant_point(ctx)
    if not settings.weather_online:
        return "Error: weather lookups are switched off (BONGO_WEATHER_ONLINE=0)."
    r = httpx.get("https://api.open-meteo.com/v1/forecast", timeout=15, params={
        "latitude": lat, "longitude": lng, "timezone": "Africa/Harare", "past_days": 1, "forecast_days": 2,
        "daily": "temperature_2m_max,temperature_2m_min,precipitation_sum,precipitation_probability_max,wind_speed_10m_max"})
    r.raise_for_status()
    d = r.json()["daily"]
    spray_ok = (d["precipitation_probability_max"][1] or 0) < 30 and (d["wind_speed_10m_max"][1] or 0) < 15
    return {"source": "open-meteo.com", "location": name, "farmDate": d["time"][1],
            "yesterdayRainMm": d["precipitation_sum"][0], "todayHighC": d["temperature_2m_max"][1],
            "todayLowC": d["temperature_2m_min"][1], "rainChancePct": d["precipitation_probability_max"][1],
            "maxWindKmh": d["wind_speed_10m_max"][1], "sprayWindowOk": spray_ok}


# --- UserInterfaceCommandPlugin ---------------------------------------------------------------

@tool("UserInterfaceCommandPlugin", "Sends up to 4 clickable choices to the user. Use whenever you ask the user to pick "
      "among discrete options. Each suggestion is the full choice text.")
def SendSuggestions(ctx: ToolContext, suggestion1: Annotated[str, "First choice"],
                    suggestion2: Annotated[str | None, "Second choice"] = None,
                    suggestion3: Annotated[str | None, "Third choice"] = None,
                    suggestion4: Annotated[str | None, "Fourth choice"] = None,
                    contextMessage: Annotated[str | None, "Optional prompt shown above the choices"] = None):
    items = [s[:200] for s in (suggestion1, suggestion2, suggestion3, suggestion4) if s]
    # A suggestion that looks like a confirmation label is dropped: only the server mints those.
    items = [s for s in items if not s.lower().startswith("confirm ")]
    ctx.emit({"type": "suggestion", "suggestions": items, "contextMessage": contextMessage})
    return "Suggestions shown to the user."


@tool("UserInterfaceCommandPlugin", "Displays a notification to the user for important messages, confirmations, warnings, or errors.")
def SendNotification(ctx: ToolContext, message: Annotated[str, "The notification message"],
                     level: Annotated[str, "info, success, warning, or error"] = "info"):
    ctx.emit({"type": "notification", "message": message[:500],
              "level": level if level in ("info", "success", "warning", "error") else "info"})
    return "Notification shown."


@tool("UserInterfaceCommandPlugin", "Shows GPS pins on a map. Only call this with real latitude/longitude (scout GPS, "
      "section centroids from GetLocations). Never pass 0,0 or invented coordinates.")
def SendMapData(ctx: ToolContext, markersJson: Annotated[str, "JSON array of markers with lat, lng, title, optional description"]):
    try:
        markers = json.loads(markersJson)
        assert isinstance(markers, list)
    except (json.JSONDecodeError, AssertionError):
        return "Error: markersJson must be a JSON array."
    clean = []
    for m in markers[:200]:
        try:
            lat, lng = float(m["lat"]), float(m["lng"])
        except (KeyError, TypeError, ValueError):
            continue
        if abs(lat) < 0.001 and abs(lng) < 0.001:
            continue
        clean.append({"lat": lat, "lng": lng, "title": str(m.get("title", ""))[:100],
                      "description": str(m.get("description", ""))[:300]})
    if not clean:
        return "Error: no usable markers (need real lat/lng)."
    ctx.emit({"type": "map", "markers": clean})
    return f"Map shown with {len(clean)} marker(s)."


@tool("UserInterfaceCommandPlugin", "Sends a table to a side panel. dataJson is an array of flat objects.")
def SendDataToPanel(ctx: ToolContext, dataJson: Annotated[str, "JSON array of row objects"],
                    title: Annotated[str, "Panel title"] = "Data"):
    try:
        data = json.loads(dataJson)
        assert isinstance(data, list)
    except (json.JSONDecodeError, AssertionError):
        return "Error: dataJson must be a JSON array of objects."
    ctx.emit({"type": "table", "title": title[:100], "rows": data[:200]})
    return "Table shown."


# --- HarnessPlugin ---------------------------------------------------------------------------

SKILLS = {
    "read-a-section": ("1.0.0", "Look up a farm section by name before using its id.",
                       "# Read a section\n\n1. Call GetLocations with the name the user gave.\n2. If several sections match, "
                       "list them and ask which one. Do not guess an id.\n3. Use the returned id in later tool calls. "
                       "Repeat the section name in the reply so the user can check it."),
    "plan-before-write": ("1.0.0", "When the user asks for a plan, switch to plan mode before any farm write.",
                          "# Plan before write\n\n1. If the user asked to plan, review, or look first, call EnterPlanMode "
                          "with their request. Do not call CreateActivity, AuthoriseActivity, or StartActivity in this turn.\n"
                          "2. Read the plan the tool returns and show it to the user.\n3. Wait for the user to say to go ahead before any write."),
    "weekly-scout-review": ("1.0.0", "Summarise the last 7 days of scouting by section with pressure vs threshold.",
                            "# Weekly scout review\n\n1. Call GetDateAndTime.\n2. Call GetScoutPressure for the last 7 days.\n"
                            "3. Call GetScoutSectionAges.\n4. Report per section: trees scouted, top findings with incidence %, "
                            "days since last scouted. Flag sections over threshold and sections not scouted in 10+ days."),
}
SUBAGENTS = {
    "explore": "Reads farm data to answer a question. Returns findings only.",
    "plan": "Plan mode. Looks up what the request needs and returns a numbered plan. Never writes.",
}


@tool("HarnessPlugin", "List skills the user can invoke. Returns names and descriptions only, not the skill body.")
def ListSkills(ctx: ToolContext):
    return "Skills:\n" + "\n".join(f"- {n} (v{v[0]}): {v[1]}" for n, v in SKILLS.items()) + \
        "\nCall LoadSkill with a name to bring that procedure into this turn."


@tool("HarnessPlugin", "Invoke a skill by name. Returns its procedure so you follow it for this turn.")
def LoadSkill(ctx: ToolContext, name: Annotated[str, "Skill name, e.g. read-a-section"]):
    skill = SKILLS.get(name.strip().lower())
    return f"Skill {name} v{skill[0]}\n\n{skill[2]}" if skill else f"Unknown skill '{name}'.\n" + ListSkills(ctx)


@tool("HarnessPlugin", "List subagent profiles. explore reads data. plan is plan mode and returns a plan without writing.")
def ListSubagents(ctx: ToolContext):
    return "Profiles:\n" + "\n".join(f"- {k}: {v}" for k, v in SUBAGENTS.items())


@tool("HarnessPlugin", "Start a subagent with a profile name and a task. It does not see this chat, can read farm data, "
      "cannot write, and cannot start another subagent.")
def StartSubagent(ctx: ToolContext, profile: Annotated[str, "explore or plan"],
                  task: Annotated[str, "The task in plain language, with names and ids the user gave"]):
    if profile not in SUBAGENTS:
        return f"Error: unknown profile '{profile}'. Use explore or plan."
    if ctx.state.subagent_runner is None:
        return "Error: subagents need an LLM provider; none is configured."
    return ctx.state.subagent_runner(profile, task, ctx.state)


@tool("HarnessPlugin", "Enter plan mode. Looks up what the request needs and returns a plan. Does not create, "
      "authorise, or start anything.")
def EnterPlanMode(ctx: ToolContext, task: Annotated[str, "What the user wants planned"]):
    return StartSubagent(ctx, "plan", task)
