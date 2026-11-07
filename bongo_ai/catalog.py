"""Which tools a caller may use: a port of ChatToolCatalog + ToolConfirmation's gated set,
plus the prompt-injection classification (whose output is trusted, which calls are writes or outbound)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .registry import TOOLS, ToolDef
from .security import Perm, Principal, can_use_chat_write_tools

HARNESS_PLUGIN = "HarnessPlugin"
UI_PLUGIN = "UserInterfaceCommandPlugin"
REMOTE_PREFIX = "Remote:"

MUTATING = {
    "CreateActivity", "ProposeSprayPurchaseTask", "EditActivity", "DiscardActivity", "CompleteActivity",
    "HoldActivity", "AuthoriseActivity", "StartActivity", "SetActivityActuals",
    "CreateObservation", "GeneratePestDiseaseSprayAnalysis", "GeneratePestSprayAnalysis",
}

# Writes the unattended spray planner (unauthenticated calendar identity) may still call.
CALENDAR_PROPOSE = {
    "CreateActivity", "EditActivity", "ProposeSprayPurchaseTask",
    "GeneratePestDiseaseSprayAnalysis", "GeneratePestSprayAnalysis",
}

# Always need the user's own message to be the exact confirmation label.
# (The C# list also gates the two Google Sheet imports, which this demo leaves out.)
GATED = {"AuthoriseActivity", "StartActivity"}

# Tools whose output contains no free text written by people or outside systems: fixed strings,
# numbers, ids, section codes and lookup names this app controls. Everything else is UNTRUSTED
# by default, so a new tool is safe until someone decides otherwise.
TRUSTED_OUTPUT = {
    "GetDateAndTime", "GetLookupGroups", "GetLookupSubGroups", "GetLocations", "GetObservationTypes",
    "GetLatestObservationDates", "GetScoutSectionAges", "GetFuelTanks", "GetFuelUsageMonthly",
    "GetWeather", "GetFarmWeatherBrief", "CheckChemicalStock", "GetReportGroups", "GetSprintFolders",
    "GetAListOfTaskTypes", "ListSkills", "LoadSkill", "ListSubagents",
    "SendSuggestions", "SendNotification", "SendMapData", "SendDataToPanel",
    # Writes whose result only echoes what the model itself sent plus server-built text (ids, states,
    # section codes). Writes that echo a stored title or reason (Complete, Hold, Edit...) stay untrusted.
    "CreateActivity", "CreateObservation", "SetActivityActuals", "ProposeSprayPurchaseTask",
}

# The assistant must not read what the person could not see in the app: a plugin's tools need the
# matching view permission (the same one the REST endpoints check). Plugins not listed need only p-ai.
PLUGIN_PERMISSIONS = {
    "ObservationsPlugin": Perm.VIEW_OBSERVATIONS, "ScoutSessionsPlugin": Perm.VIEW_OBSERVATIONS,
    "ActivitiesPlugin": Perm.VIEW_ACTIVITIES, "ChemicalPlugin": Perm.VIEW_CHEMICALS,
    "FuelPlugin": Perm.VIEW_FUEL, "ReportsPlugin": Perm.VIEW_REPORT,
}

# Writes that only regenerate a derived report from the farm's own data: allowed in a tainted
# conversation without a confirmation, because no attacker-chosen text decides what they write.
TAINT_EXEMPT_WRITES = {"GeneratePestDiseaseSprayAnalysis", "GeneratePestSprayAnalysis"}


def is_remote(name: str | None) -> bool:
    td = TOOLS.get(name or "")
    return bool(td and td.remote)


def is_mutating(name: str | None) -> bool:
    """Local writes, plus remote tools that do not declare readOnlyHint=true."""
    td = TOOLS.get(name or "")
    if td and td.remote:
        return not td.remote.get("read_only")
    return name in MUTATING


def is_gated(name: str | None) -> bool:
    """Always needs confirmation, tainted or not: Authorise/Start and every remote write."""
    return name in GATED or (is_remote(name) and is_mutating(name))


def trusted_output(name: str | None) -> bool:
    return name in TRUSTED_OUTPUT and not is_remote(name)


def needs_confirmation_when_tainted(name: str | None) -> bool:
    """Writes and outbound calls (anything sent to a remote server) once untrusted text is in context."""
    if name in TAINT_EXEMPT_WRITES:
        return False
    return is_mutating(name) or is_remote(name)


@dataclass
class ToolAccess:
    tool: ToolDef
    allowed: bool
    reason: str = ""


def explain(principal: Principal, template_tools: list[str] | None = None, channel: str = "chat") -> list[ToolAccess]:
    """Every tool with a yes/no and the rule that decided it (used by the Security page)."""
    patterns = [re.compile(p, re.IGNORECASE) for p in (template_tools or [])]
    leadership = can_use_chat_write_tools(principal.rolename)
    out: list[ToolAccess] = []
    for td in TOOLS.values():
        reason = ""
        mutating = is_mutating(td.name)
        if td.remote and td.remote.get("tenants") and principal.tenant_id not in td.remote["tenants"]:
            reason = "External server is not enabled for this farm"
        elif patterns and td.plugin != HARNESS_PLUGIN and not any(p.search(td.plugin) for p in patterns):
            reason = "Not in this chat template's tool list"
        elif principal.is_authenticated and td.plugin in PLUGIN_PERMISSIONS \
                and not principal.has(PLUGIN_PERMISSIONS[td.plugin]):
            reason = f"Needs permission {PLUGIN_PERMISSIONS[td.plugin]} to read {td.plugin} data"
        elif not principal.is_authenticated:
            if td.plugin == HARNESS_PLUGIN:
                reason = "Skills and subagents are for a signed-in person"
            elif td.remote:
                reason = "External tools need a signed-in person"
            elif mutating and td.name not in CALENDAR_PROPOSE:
                reason = "Calendar identity may only propose"
        elif mutating and not leadership:
            reason = f"Role '{principal.rolename}' is not farm leadership: no write tools"
        if not reason and channel == "mcp":
            if td.plugin in (UI_PLUGIN, HARNESS_PLUGIN):
                reason = "Chat-only tool, not exposed over MCP"
            elif td.remote:
                reason = "External tools are not re-exported over MCP"
            elif is_gated(td.name):
                reason = "Needs an in-chat human confirmation, so it is withheld from MCP"
        out.append(ToolAccess(td, not reason, reason))
    return out


def permitted(principal: Principal, template_tools: list[str] | None = None, channel: str = "chat") -> list[ToolDef]:
    return [a.tool for a in explain(principal, template_tools, channel) if a.allowed]


def for_subagent(principal: Principal) -> list[ToolDef]:
    """Farm reads the parent's user may use. No writes, no UI commands, no harness (so a child cannot
    start a child), and no external tools (a subagent cannot ask anyone to confirm an outbound call)."""
    return [td for td in permitted(principal)
            if td.plugin not in (HARNESS_PLUGIN, UI_PLUGIN) and not is_mutating(td.name) and not td.remote]
