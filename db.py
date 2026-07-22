import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# 모든 쿼리는 ? 파라미터 바인딩만 사용한다 (SQL Injection 차단)
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            isolation_level=None,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db

def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def query_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()

def query_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()

def execute(sql, params=()):
    cur = get_db().execute(sql, params)
    return cur.lastrowid

def init_db(app):
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        _seed_admin(db, app)

def _seed_admin(db, app):
    from werkzeug.security import generate_password_hash

    admin = db.execute(
        "SELECT id FROM users WHERE username = ?", ("admin",)
    ).fetchone()
    if admin is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role, balance) "
            "VALUES (?, ?, 'admin', 0)",
            ("admin", generate_password_hash(app.config["ADMIN_PASSWORD"])),
        )
        app.logger.info("Seeded default admin account (username=admin).")

def audit(actor_id, action, target="", detail=""):
    execute(
        "INSERT INTO audit_logs (actor_id, action, target, detail) "
        "VALUES (?, ?, ?, ?)",
        (actor_id, action, target, detail),
    )
