"""
storage.py
----------
SQLite-backed storage for short links.

Why SQLite instead of a single JSON file:
- Safe concurrent access across multiple gunicorn workers (the JSON-file /
  "atomic write" approach breaks down under concurrent writers because each
  worker process has its own in-memory view of the file).
- Built-in transactions instead of hand-rolled atomicity.
- Cheap indexed lookups instead of loading/parsing the whole file per request.
- Zero extra infra to run (single file on disk, same deployment story as JSON).
"""

import json
import sqlite3
import time
import threading
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "sub_aggregator.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS short_links (
    code        TEXT PRIMARY KEY,
    urls        TEXT NOT NULL,      -- JSON-encoded list of source URLs
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    node_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS node_cache (
    code        TEXT PRIMARY KEY,
    nodes       TEXT NOT NULL,      -- JSON-encoded list of normalized node dicts
    cached_at   REAL NOT NULL,
    FOREIGN KEY(code) REFERENCES short_links(code) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_expires_at ON short_links(expires_at);
"""


def _get_conn():
    """One connection per thread; gunicorn sync workers are single-threaded
    per process so this keeps things simple and safe."""
    if not hasattr(_local, "conn"):
        conn = sqlite3.connect(str(DB_PATH), timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")  # allows concurrent readers + one writer
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA)
        _local.conn = conn
    return _local.conn


@contextmanager
def _tx():
    conn = _get_conn()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def create_short_link(code: str, urls: list[str], ttl_seconds: int, node_count: int = 0):
    now = time.time()
    with _tx() as conn:
        conn.execute(
            "INSERT INTO short_links (code, urls, created_at, expires_at, node_count) "
            "VALUES (?, ?, ?, ?, ?)",
            (code, json.dumps(urls), now, now + ttl_seconds, node_count),
        )


def get_short_link(code: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT code, urls, created_at, expires_at, node_count FROM short_links WHERE code = ?",
        (code,),
    ).fetchone()
    if not row:
        return None
    code_, urls_json, created_at, expires_at, node_count = row
    if expires_at < time.time():
        delete_short_link(code_)
        return None
    return {
        "code": code_,
        "urls": json.loads(urls_json),
        "created_at": created_at,
        "expires_at": expires_at,
        "node_count": node_count,
    }


def delete_short_link(code: str):
    with _tx() as conn:
        conn.execute("DELETE FROM node_cache WHERE code = ?", (code,))
        conn.execute("DELETE FROM short_links WHERE code = ?", (code,))


def get_cached_nodes(code: str, max_age_seconds: int) -> list[dict] | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT nodes, cached_at FROM node_cache WHERE code = ?", (code,)
    ).fetchone()
    if not row:
        return None
    nodes_json, cached_at = row
    if time.time() - cached_at > max_age_seconds:
        return None
    return json.loads(nodes_json)


def set_cached_nodes(code: str, nodes: list[dict]):
    now = time.time()
    with _tx() as conn:
        conn.execute(
            "INSERT INTO node_cache (code, nodes, cached_at) VALUES (?, ?, ?) "
            "ON CONFLICT(code) DO UPDATE SET nodes = excluded.nodes, cached_at = excluded.cached_at",
            (code, json.dumps(nodes), now),
        )
        conn.execute(
            "UPDATE short_links SET node_count = ? WHERE code = ?",
            (len(nodes), code),
        )


def purge_expired() -> int:
    """Delete all short links (and their cache rows) past expiry.
    Call this from a scheduled job / background thread, not per-request."""
    now = time.time()
    with _tx() as conn:
        expired = [
            r[0] for r in conn.execute(
                "SELECT code FROM short_links WHERE expires_at < ?", (now,)
            ).fetchall()
        ]
        if expired:
            conn.executemany("DELETE FROM node_cache WHERE code = ?", [(c,) for c in expired])
            conn.executemany("DELETE FROM short_links WHERE code = ?", [(c,) for c in expired])
    return len(expired)


def stats() -> dict:
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM short_links").fetchone()[0]
    return {"active_short_links": total}
