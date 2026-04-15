"""
history.py — SQLite-backed alert history store.

Keeps the last HISTORY_LIMIT alerts per (rule_id, agent_name) so the AI
can compare consecutive alerts of the same type (e.g. netstat port changes).
"""

import os
import sqlite3
import threading
from datetime import datetime
from parser import WazuhAlert

DB_PATH        = os.environ.get("ALERT_DB_PATH", "/data/alerts.db")
HISTORY_LIMIT  = int(os.environ.get("ALERT_HISTORY_LIMIT", "3"))
HISTORY_RULES  = {"533"}  # only store/compare history for these rule IDs

_local = threading.local()


def _conn() -> sqlite3.Connection:
    """Return a thread-local DB connection, creating schema on first use."""
    if not hasattr(_local, "conn"):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id         TEXT    NOT NULL,
                agent_name      TEXT    NOT NULL,
                agent_ip        TEXT,
                rule_level      INTEGER,
                rule_description TEXT,
                full_log        TEXT,
                received_at     TEXT    NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rule_agent "
            "ON alert_history(rule_id, agent_name)"
        )
        conn.commit()
        _local.conn = conn
    return _local.conn


def save_alert(alert: WazuhAlert) -> None:
    """Persist alert and prune old entries beyond HISTORY_LIMIT.
    Only stores alerts for rule IDs in HISTORY_RULES."""
    if alert.rule_id not in HISTORY_RULES:
        return
    conn = _conn()
    conn.execute(
        """INSERT INTO alert_history
           (rule_id, agent_name, agent_ip, rule_level, rule_description, full_log, received_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            alert.rule_id,
            alert.agent_name,
            alert.agent_ip,
            alert.rule_level,
            alert.rule_description,
            alert.full_log,
            datetime.utcnow().isoformat(sep=" ", timespec="seconds"),
        ),
    )
    # Keep only the most recent HISTORY_LIMIT rows per (rule_id, agent_name)
    conn.execute(
        """DELETE FROM alert_history
           WHERE rule_id = ? AND agent_name = ?
             AND id NOT IN (
               SELECT id FROM alert_history
               WHERE rule_id = ? AND agent_name = ?
               ORDER BY id DESC LIMIT ?
             )""",
        (alert.rule_id, alert.agent_name, alert.rule_id, alert.agent_name, HISTORY_LIMIT),
    )
    conn.commit()


def get_previous_alerts(alert: WazuhAlert, limit: int = 2) -> list[sqlite3.Row]:
    """Return up to `limit` previous alerts for the same rule + agent, newest first.
    Excludes the most recent row (which is the one just saved).
    Returns empty list for rules not in HISTORY_RULES."""
    if alert.rule_id not in HISTORY_RULES:
        return []
    conn = _conn()
    rows = conn.execute(
        """SELECT full_log, received_at FROM alert_history
           WHERE rule_id = ? AND agent_name = ?
           ORDER BY id DESC
           LIMIT ? OFFSET 1""",
        (alert.rule_id, alert.agent_name, limit),
    ).fetchall()
    return rows
