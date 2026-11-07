"""Review and approve (pin) the tools of the remote MCP servers in mcp_servers.json.

A tool reaches the model only when its exact definition has been approved here. Run this after
adding a server, and again whenever the app logs "mcp_tool_changed".

    python scripts/mcp_pin.py                      # review every server, prompt per new/changed tool
    python scripts/mcp_pin.py --server agronomy    # one server
    python scripts/mcp_pin.py --approve get_soil_report --yes
    python scripts/mcp_pin.py --revoke get_soil_report

Read the full description and schema before approving: that text goes to the model verbatim,
so it is where a malicious server would hide instructions.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from bongo_ai import remote_mcp  # noqa: E402
from bongo_ai.config import settings  # noqa: E402
from bongo_ai.executor import scan_for_injection  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=settings.mcp_servers_file)
    ap.add_argument("--server")
    ap.add_argument("--approve", action="append", default=[], help="tool name to approve (repeatable)")
    ap.add_argument("--revoke", action="append", default=[], help="tool name to remove from the pins")
    ap.add_argument("--yes", action="store_true", help="do not prompt; approve only what --approve names")
    a = ap.parse_args()
    if not a.config.exists():
        sys.exit(f"{a.config} not found. Copy mcp_servers.example.json to start.")
    config = json.loads(a.config.read_text(encoding="utf-8"))
    changed = False

    for cfg in config.get("servers", []):
        if a.server and cfg.get("name") != a.server:
            continue
        pins: dict[str, str] = cfg.setdefault("pinnedTools", {})
        for name in a.revoke:
            if pins.pop(name, None):
                print(f"Revoked {cfg['name']}/{name}")
                changed = True
        try:
            server = remote_mcp.RemoteServer(cfg)
            server.connect()
            tools = server.list_tools()
        except Exception as exc:
            print(f"! {cfg.get('name')}: cannot connect: {exc}")
            continue
        print(f"\n== {cfg['name']}  {cfg['url']}  ({len(tools)} tools)")
        for tool in tools:
            name, pin = tool["name"], remote_mcp.tool_pin(tool)
            state = "approved" if pins.get(name) == pin else "CHANGED" if name in pins else "new"
            read_only = (tool.get("annotations") or {}).get("readOnlyHint") is True
            print(f"\n- {name}  [{state}]  {'read-only' if read_only else 'WRITE (always needs confirmation)'}")
            print(f"  pin: {pin}")
            if state == "approved" and name not in a.approve:
                continue
            text = json.dumps(tool, indent=2, ensure_ascii=False)
            print("  definition:\n    " + text.replace("\n", "\n    "))
            flags = scan_for_injection((tool.get("description") or "") + json.dumps(tool.get("inputSchema") or {}))
            if flags:
                print(f"  !! description looks like it contains instructions to an AI: {', '.join(flags)}")
            approve = name in a.approve
            if not approve and not a.yes:
                approve = input(f"  Approve {name}? [y/N] ").strip().lower() == "y"
            if approve:
                pins[name] = pin
                changed = True
                print(f"  approved {name}")
        for gone in sorted(set(pins) - {t["name"] for t in tools}):
            print(f"\n- {gone}  [pinned but no longer offered by the server]")

    if changed:
        a.config.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        print(f"\nSaved {a.config}. Restart the server to load the approved tools.")


if __name__ == "__main__":
    main()
