"""SQLite storage. One file, created by scripts/seed.py.

Every farm table carries tenant_id. Tools read the tenant from the caller's
token, never from model-supplied arguments, so one tenant cannot see another's data.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .config import settings

SCHEMA = """
PRAGMA foreign_keys = ON;

-- identity & access --------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY, company_id TEXT NOT NULL, site_id TEXT NOT NULL, name TEXT NOT NULL,
    latitude REAL, longitude REAL
);
CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, rolename TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS permissions (code TEXT PRIMARY KEY, description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id), permission_code TEXT NOT NULL REFERENCES permissions(code),
    PRIMARY KEY (role_id, permission_code)
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, pwd TEXT NOT NULL,
    given_name TEXT NOT NULL, family_name TEXT, role_id TEXT NOT NULL REFERENCES roles(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id), is_locked INTEGER NOT NULL DEFAULT 0,
    is_disabled INTEGER NOT NULL DEFAULT 0, is_temporary INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0, lockout_until TEXT
);
CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL, revoked_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, tenant_id TEXT, username TEXT,
    event TEXT NOT NULL, detail TEXT, ip TEXT
);

-- farm reference data -------------------------------------------------------
CREATE TABLE IF NOT EXISTS farm_sections (
    id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), code TEXT NOT NULL,
    area_m2 INTEGER, centroid_lat REAL, centroid_lng REAL, polygon_json TEXT, is_orchard INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS lookup_groups (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lookup_sub_groups (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL REFERENCES lookup_groups(id), name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lookup_items (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL REFERENCES lookup_groups(id),
    sub_group_id TEXT REFERENCES lookup_sub_groups(id), name TEXT NOT NULL, description TEXT
);

-- observations -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS observation_types (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, is_active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER
);
CREATE TABLE IF NOT EXISTS observation_type_data_points (
    id TEXT PRIMARY KEY, observation_type_id TEXT NOT NULL REFERENCES observation_types(id), code TEXT NOT NULL,
    label TEXT NOT NULL, data_type TEXT NOT NULL, is_required INTEGER NOT NULL DEFAULT 0, sort_order INTEGER
);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, observation_type_id TEXT REFERENCES observation_types(id),
    summary TEXT, notes TEXT, severity TEXT, timestamp TEXT NOT NULL, farm_location_id TEXT,
    tree_line_number INTEGER, tree_number TEXT, latitude REAL, longitude REAL,
    created_by TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observation_metadata (
    id TEXT PRIMARY KEY, observation_id TEXT NOT NULL REFERENCES observations(id), data_point_id TEXT NOT NULL, value TEXT
);

-- scout sessions (orchard walks) ------------------------------------------------
CREATE TABLE IF NOT EXISTS scout_sessions (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, section_code TEXT, farm_location_id TEXT,
    scout_date TEXT NOT NULL, notes TEXT, phenology_stage TEXT, orchard_checks_json TEXT,
    status TEXT NOT NULL, created_by TEXT, created_at TEXT, updated_at TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS scout_session_trees (
    id TEXT PRIMARY KEY, scout_session_id TEXT NOT NULL REFERENCES scout_sessions(id), sort_order INTEGER NOT NULL,
    tree_line_number INTEGER, tree_number TEXT, latitude REAL, longitude REAL, notes TEXT, plant_health TEXT,
    nothing_found INTEGER NOT NULL DEFAULT 0, pest_findings_json TEXT, disease_findings_json TEXT,
    beneficial_findings_json TEXT, photo_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_scout_sessions_tenant_date ON scout_sessions(tenant_id, scout_date);
CREATE INDEX IF NOT EXISTS ix_scout_trees_session ON scout_session_trees(scout_session_id);

-- activities ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS activities (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, activity_type TEXT NOT NULL, state TEXT NOT NULL,
    title TEXT, description TEXT, reason TEXT, priority TEXT, farm_section_ids TEXT, details_json TEXT,
    planned_start TEXT, planned_end TEXT, team TEXT, estimated_team_size INTEGER, equipment_needed TEXT,
    created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT NOT NULL REFERENCES activities(id),
    at TEXT NOT NULL, actor TEXT NOT NULL, from_state TEXT, to_state TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS activity_actuals (
    id TEXT PRIMARY KEY, activity_id TEXT NOT NULL REFERENCES activities(id), work_date TEXT NOT NULL,
    permanent_staff INTEGER, temporary_workers INTEGER, supervisor TEXT, equipment TEXT, notes TEXT,
    recorded_by TEXT, recorded_at TEXT
);

-- chemicals, equipment, fuel ------------------------------------------------------
CREATE TABLE IF NOT EXISTS chemicals (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, type TEXT, notes TEXT, description TEXT,
    target TEXT, irac_code TEXT, frac_code TEXT, min_rate_per_100l REAL, max_rate_per_100l REAL, rate_unit TEXT,
    phi_days INTEGER, price REAL, price_currency TEXT, stock_on_hand REAL, stock_unit TEXT,
    is_sprayable INTEGER NOT NULL DEFAULT 1, is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS equipment (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, equipment_type TEXT, serial_number TEXT,
    location TEXT, status TEXT, service_interval_hours INTEGER, current_hours REAL, last_service_hours REAL,
    last_service_date TEXT, notes TEXT, is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS equipment_service_logs (
    id TEXT PRIMARY KEY, equipment_id TEXT NOT NULL REFERENCES equipment(id), service_type TEXT, description TEXT,
    performed_by TEXT, service_date TEXT NOT NULL, hours_at_service REAL, cost REAL, notes TEXT
);
CREATE TABLE IF NOT EXISTS fuel_tanks (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, unit TEXT NOT NULL DEFAULT 'L', sort_order INTEGER
);
CREATE TABLE IF NOT EXISTS fuel_machines (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT,
    fuel_tank_id TEXT REFERENCES fuel_tanks(id), has_meter INTEGER NOT NULL DEFAULT 0, meter_unit TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS fuel_movements (
    id TEXT PRIMARY KEY, fuel_tank_id TEXT NOT NULL REFERENCES fuel_tanks(id), kind TEXT NOT NULL,
    quantity_litres REAL NOT NULL, occurred_on TEXT NOT NULL, machine_id TEXT REFERENCES fuel_machines(id),
    notes TEXT, authorised_by TEXT, source TEXT
);

-- reports & boards -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_groups (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES report_groups(id), title TEXT NOT NULL,
    description TEXT, content_md TEXT NOT NULL, produced_at TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS boards (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, folder TEXT NOT NULL, name TEXT NOT NULL,
    start_date TEXT NOT NULL, end_date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS board_tasks (
    id TEXT PRIMARY KEY, board_id TEXT NOT NULL REFERENCES boards(id), title TEXT NOT NULL, task_type TEXT,
    status TEXT, assignee TEXT, start_date TEXT, created_at TEXT NOT NULL, notes TEXT
);

-- chat ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chat_conversations (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, title TEXT, template_id TEXT,
    provider TEXT, llm_history_json TEXT NOT NULL DEFAULT '[]', pending_tool_json TEXT, taint_json TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL REFERENCES chat_conversations(id),
    role TEXT NOT NULL, content TEXT, tool_name TEXT, tool_args_json TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, tenant_id TEXT, user_id TEXT, username TEXT,
    rolename TEXT, channel TEXT NOT NULL, conversation_id TEXT, tool_name TEXT NOT NULL, arguments_json TEXT,
    outcome TEXT NOT NULL, detail TEXT
);

CREATE TABLE IF NOT EXISTS demo_meta (key TEXT PRIMARY KEY, value TEXT);
"""

_local = threading.local()
_write_lock = threading.Lock()  # SQLite allows one writer; serialise writes from worker threads.


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = Path(path or settings.db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    path = str(settings.db_path)
    if conn is None or getattr(_local, "path", None) != path:
        conn = connect()
        migrate(conn)
        _local.conn, _local.path = conn, path
    return conn


# Columns added after the first release, so databases seeded earlier keep working.
_ADDED_COLUMNS = {"chat_conversations": {"taint_json": "TEXT"}}


def migrate(conn: sqlite3.Connection) -> None:
    for table, columns in _ADDED_COLUMNS.items():
        existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue  # schema not created yet (seed will create it)
        for name, decl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    conn.commit()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def rows(sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in get_conn().execute(sql, params).fetchall()]


def row(sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
    r = get_conn().execute(sql, params).fetchone()
    return dict(r) if r else None


def scalar(sql: str, params: tuple | list = ()) -> Any:
    r = get_conn().execute(sql, params).fetchone()
    return r[0] if r else None


@contextmanager
def write() -> Iterator[sqlite3.Connection]:
    conn = get_conn()
    with _write_lock:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
