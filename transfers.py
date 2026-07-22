import sqlite3

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

from db import audit, execute, get_db, query_all, query_one
from security import login_required

bp = Blueprint("transfers", __name__, url_prefix="/transfers")

MAX_AMOUNT = 100_000_000
DEMO_CHARGE = 100_000

@bp.route("/")
@login_required
def index():
    me = g.user["id"]
    history = query_all(
        "SELECT t.*, "
        "  s.username AS sender_name, r.username AS receiver_name "
        "FROM transfers t "
        "JOIN users s ON s.id = t.sender_id "
        "JOIN users r ON r.id = t.receiver_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 50",
        (me, me),
    )
    return render_template("transfers/index.html",
                           balance=g.user["balance"], history=history)

@bp.route("/send", methods=("POST",))
@login_required
def send():
    me = g.user["id"]
    to_username = request.form.get("to_username", "").strip()
    amount_raw = request.form.get("amount", "").strip()
    memo = request.form.get("memo", "").strip()[:200]

    if not amount_raw.isdigit() or int(amount_raw) <= 0:
        flash("송금액은 1 이상의 정수여야 합니다.", "danger")
        return redirect(url_for("transfers.index"))
    amount = int(amount_raw)
    if amount > MAX_AMOUNT:
        flash("송금액이 허용 범위를 초과했습니다.", "danger")
        return redirect(url_for("transfers.index"))

    receiver = query_one(
        "SELECT id, status FROM users WHERE username = ?", (to_username,)
    )
    if receiver is None or receiver["status"] == "suspended":
        flash("받는 사람을 찾을 수 없습니다.", "danger")
        return redirect(url_for("transfers.index"))
    if receiver["id"] == me:
        flash("자기 자신에게는 송금할 수 없습니다.", "danger")
        return redirect(url_for("transfers.index"))

    ok, msg = _do_transfer(me, receiver["id"], amount, memo)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("transfers.index"))

def _do_transfer(sender_id, receiver_id, amount, memo):
    db = get_db()
    try:
        # 즉시 쓰기잠금으로 동시 송금을 직렬화 (TOCTOU 이중 사용 방어)
        db.execute("BEGIN IMMEDIATE")
        sender = db.execute(
            "SELECT balance FROM users WHERE id = ?", (sender_id,)
        ).fetchone()
        if sender is None:
            db.execute("ROLLBACK")
            return False, "송금자 정보를 찾을 수 없습니다."
        if sender["balance"] < amount:
            db.execute("ROLLBACK")
            return False, "잔액이 부족합니다."

        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?",
                   (amount, sender_id))
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
                   (amount, receiver_id))
        db.execute(
            "INSERT INTO transfers (sender_id, receiver_id, amount, memo) "
            "VALUES (?, ?, ?, ?)",
            (sender_id, receiver_id, amount, memo),
        )
        db.execute("COMMIT")
        return True, f"{amount:,}원을 송금했습니다."
    except sqlite3.IntegrityError:
        db.execute("ROLLBACK")
        return False, "잔액이 부족합니다."
    except sqlite3.Error:
        db.execute("ROLLBACK")
        return False, "송금 처리 중 오류가 발생했습니다."

@bp.route("/charge", methods=("POST",))
@login_required
def charge():
    execute("UPDATE users SET balance = balance + ? WHERE id = ?",
            (DEMO_CHARGE, g.user["id"]))
    audit(g.user["id"], "demo_charge", f"user:{g.user['id']}", str(DEMO_CHARGE))
    flash(f"[데모] {DEMO_CHARGE:,}원이 충전되었습니다.", "info")
    return redirect(url_for("transfers.index"))
