"""Replace the demo's scout sessions with the live BongoFMS data from the last N days.

Run seed.py first (it builds every other table), then:

    pip install "psycopg[binary]"
    kubectl --context microk8s port-forward svc/<postgres-service> 35432:5432   # in another terminal
    set BONGO_PG_DSN=host=localhost port=35432 dbname=bongo user=docker password=...
    python scripts/import_postgres.py --days 31

Read-only against PostgreSQL: it only runs SELECTs. Scout dates are converted with the same
rule as ScoutCalendarDate.ToFarmDate (timestamptz -> Africa/Harare calendar day).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from bongo_ai import db  # noqa: E402
from bongo_ai.config import FARM_TZ, settings  # noqa: E402

BONGO = "5a51b02f-d3f6-4186-8321-0090e4d4e7ca"


def farm_date(value) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.date().isoformat()          # Unspecified midnight is already a date
        return value.astimezone(FARM_TZ).date().isoformat()
    return str(value)[:10]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=31)
    ap.add_argument("--dsn", default=os.environ.get("BONGO_PG_DSN", ""))
    ap.add_argument("--db", type=Path, default=settings.db_path)
    a = ap.parse_args()
    if not a.dsn:
        sys.exit("Set BONGO_PG_DSN or pass --dsn.")
    try:
        import psycopg
    except ImportError:
        sys.exit('psycopg is not installed: pip install "psycopg[binary]"')

    since = datetime.now(timezone.utc) - timedelta(days=a.days + 1)
    with psycopg.connect(a.dsn, autocommit=True) as pg, pg.cursor() as cur:
        cur.execute("SET default_transaction_read_only = on")
        cur.execute("""SELECT id, section_code, farm_location_id, scout_date, notes, phenology_stage, orchard_checks_json,
                              status, created_by, created_at, updated_at
                       FROM scout_sessions WHERE scout_date >= %s ORDER BY scout_date""", (since,))
        sessions = cur.fetchall()
        ids = [s[0] for s in sessions]
        trees, photos = [], {}
        if ids:
            cur.execute("""SELECT id, scout_session_id, sort_order, tree_line_number, tree_number, latitude, longitude, notes,
                                  plant_health, nothing_found, pest_findings_json, disease_findings_json, beneficial_findings_json
                           FROM scout_session_trees WHERE scout_session_id = ANY(%s)""", (ids,))
            trees = cur.fetchall()
            cur.execute("""SELECT scout_session_tree_id, count(*) FROM scout_session_tree_photos
                           WHERE is_active AND scout_session_tree_id = ANY(%s) GROUP BY 1""", ([t[0] for t in trees],))
            photos = dict(cur.fetchall())

    settings.db_path = a.db
    cutoff = (datetime.now(FARM_TZ).date() - timedelta(days=a.days)).isoformat()
    kept = [s for s in sessions if farm_date(s[3]) >= cutoff]
    kept_ids = {s[0] for s in kept}
    with db.write() as conn:
        conn.execute("DELETE FROM scout_session_trees WHERE scout_session_id IN (SELECT id FROM scout_sessions WHERE tenant_id = ?)", (BONGO,))
        conn.execute("DELETE FROM scout_sessions WHERE tenant_id = ?", (BONGO,))
        for s in kept:
            conn.execute("""INSERT INTO scout_sessions (id, tenant_id, section_code, farm_location_id, scout_date, notes, phenology_stage,
                            orchard_checks_json, status, created_by, created_at, updated_at, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (s[0], BONGO, s[1], s[2], farm_date(s[3]), s[4], s[5], s[6], s[7], s[8],
                          s[9].isoformat() if s[9] else None, s[10].isoformat() if s[10] else None, "bongofms postgres"))
        n = 0
        for t in trees:
            if t[1] not in kept_ids:
                continue
            n += 1
            conn.execute("""INSERT INTO scout_session_trees (id, scout_session_id, sort_order, tree_line_number, tree_number, latitude,
                            longitude, notes, plant_health, nothing_found, pest_findings_json, disease_findings_json,
                            beneficial_findings_json, photo_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], int(bool(t[9])), t[10], t[11], t[12], photos.get(t[0], 0)))
        first = min((farm_date(s[3]) for s in kept), default="-")
        last = max((farm_date(s[3]) for s in kept), default="-")
        conn.execute("INSERT OR REPLACE INTO demo_meta VALUES ('data_source', ?)",
                     (f"Live BongoFMS scouting: {len(kept)} sessions, {n} tree reports from {first} to {last}. "
                      "Sections, polygons and chemicals are real; equipment, fuel, boards, seeded activities and the "
                      "Kariba tenant are synthetic.",))
        conn.execute("INSERT OR REPLACE INTO demo_meta VALUES ('date_shift_days', '0')")
    print(f"Imported {len(kept)} sessions and {n} trees ({first} .. {last}) into {a.db}")
    print(json.dumps({"unknownSections": sorted({s[1] for s in kept if s[1] and not db.scalar(
        "SELECT 1 FROM farm_sections WHERE tenant_id = ? AND lower(code) = lower(?)", (BONGO, s[1]))})}))


if __name__ == "__main__":
    main()
