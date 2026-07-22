from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, url_for
)

from db import audit, execute, query_one
from security import login_required

bp = Blueprint("reports", __name__, url_prefix="/reports")

MAX_REASON = 500
REPORT_THRESHOLD = 3

@bp.route("/new")
@login_required
def new():
    target_type = request.args.get("target_type", "")
    target_id_raw = request.args.get("target_id", "")
    if target_type not in ("user", "product") or not target_id_raw.isdigit():
        abort(400)
    target_id = int(target_id_raw)

    if target_type == "user":
        target = query_one("SELECT id, username FROM users WHERE id = ?", (target_id,))
        label = target["username"] if target else None
    else:
        target = query_one("SELECT id, title FROM products WHERE id = ?", (target_id,))
        label = target["title"] if target else None
    if target is None:
        abort(404)

    return render_template("report_form.html",
                           target_type=target_type, target_id=target_id, label=label)

@bp.route("/create", methods=("POST",))
@login_required
def create():
    target_type = request.form.get("target_type", "")
    target_id_raw = request.form.get("target_id", "")
    reason = request.form.get("reason", "").strip()[:MAX_REASON]

    if target_type not in ("user", "product") or not target_id_raw.isdigit():
        abort(400)
    target_id = int(target_id_raw)

    if not reason:
        flash("신고 사유를 입력해 주세요.", "warning")
        return redirect(url_for("reports.new",
                                target_type=target_type, target_id=target_id))

    table = "users" if target_type == "user" else "products"
    exists = query_one(f"SELECT 1 FROM {table} WHERE id = ?", (target_id,))
    if exists is None:
        abort(404)

    if target_type == "user" and target_id == g.user["id"]:
        flash("자기 자신은 신고할 수 없습니다.", "warning")
        return redirect(url_for("products.list_products"))

    execute(
        "INSERT INTO reports (reporter_id, target_type, target_id, reason) "
        "VALUES (?, ?, ?, ?)",
        (g.user["id"], target_type, target_id, reason),
    )
    _auto_moderate(target_type, target_id)

    flash("신고가 접수되었습니다. 관리자가 검토합니다.", "success")
    return redirect(url_for("products.list_products"))

def _auto_moderate(target_type, target_id):
    # 서로 다른 신고자 수로 집계 (1인 반복 신고 악용 방지)
    distinct = query_one(
        "SELECT COUNT(DISTINCT reporter_id) AS c FROM reports "
        "WHERE target_type = ? AND target_id = ?",
        (target_type, target_id),
    )["c"]
    if distinct < REPORT_THRESHOLD:
        return

    if target_type == "product":
        prod = query_one("SELECT status FROM products WHERE id = ?", (target_id,))
        if prod and prod["status"] != "blocked":
            execute("UPDATE products SET status = 'blocked' WHERE id = ?", (target_id,))
            audit(None, "auto_block_product", f"product:{target_id}",
                  f"{distinct} distinct reporters")
    else:
        usr = query_one("SELECT status, role FROM users WHERE id = ?", (target_id,))
        if usr and usr["status"] != "suspended" and usr["role"] != "admin":
            execute("UPDATE users SET status = 'suspended' WHERE id = ?", (target_id,))
            audit(None, "auto_suspend_user", f"user:{target_id}",
                  f"{distinct} distinct reporters")
