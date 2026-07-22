from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, url_for
)

from db import audit, execute, query_all, query_one
from security import admin_required

bp = Blueprint("admin", __name__, url_prefix="/admin")

@bp.route("/")
@admin_required
def dashboard():
    stats = {
        "users": query_one("SELECT COUNT(*) c FROM users")["c"],
        "suspended": query_one(
            "SELECT COUNT(*) c FROM users WHERE status='suspended'")["c"],
        "products": query_one("SELECT COUNT(*) c FROM products")["c"],
        "blocked": query_one(
            "SELECT COUNT(*) c FROM products WHERE status='blocked'")["c"],
        "open_reports": query_one(
            "SELECT COUNT(*) c FROM reports WHERE status='open'")["c"],
    }
    return render_template("admin/dashboard.html", stats=stats)

@bp.route("/users")
@admin_required
def users():
    rows = query_all(
        "SELECT id, username, role, status, balance, created_at "
        "FROM users ORDER BY created_at DESC"
    )
    return render_template("admin/users.html", users=rows)

@bp.route("/users/<int:uid>/suspend", methods=("POST",))
@admin_required
def suspend_user(uid):
    target = query_one("SELECT * FROM users WHERE id = ?", (uid,))
    if target is None:
        abort(404)
    if target["id"] == g.user["id"]:
        flash("본인 계정은 정지할 수 없습니다.", "warning")
        return redirect(url_for("admin.users"))
    new_status = "active" if target["status"] == "suspended" else "suspended"
    execute("UPDATE users SET status = ? WHERE id = ?", (new_status, uid))
    audit(g.user["id"], f"user_{new_status}", f"user:{uid}", target["username"])
    flash(f"{target['username']} 계정을 {new_status} 상태로 변경했습니다.", "success")
    return redirect(url_for("admin.users"))

@bp.route("/users/<int:uid>/role", methods=("POST",))
@admin_required
def toggle_role(uid):
    target = query_one("SELECT * FROM users WHERE id = ?", (uid,))
    if target is None:
        abort(404)
    new_role = "user" if target["role"] == "admin" else "admin"
    if new_role == "user":
        admin_count = query_one(
            "SELECT COUNT(*) c FROM users WHERE role='admin'")["c"]
        if admin_count <= 1:
            flash("마지막 관리자는 강등할 수 없습니다.", "warning")
            return redirect(url_for("admin.users"))
    execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
    audit(g.user["id"], f"role_change_{new_role}", f"user:{uid}", target["username"])
    flash(f"{target['username']} 권한을 {new_role}(으)로 변경했습니다.", "success")
    return redirect(url_for("admin.users"))

@bp.route("/products")
@admin_required
def products():
    rows = query_all(
        "SELECT p.*, u.username AS seller_name "
        "FROM products p JOIN users u ON u.id = p.seller_id "
        "ORDER BY p.created_at DESC"
    )
    return render_template("admin/products.html", products=rows)

@bp.route("/products/<int:pid>/block", methods=("POST",))
@admin_required
def block_product(pid):
    target = query_one("SELECT * FROM products WHERE id = ?", (pid,))
    if target is None:
        abort(404)
    new_status = "available" if target["status"] == "blocked" else "blocked"
    execute("UPDATE products SET status = ? WHERE id = ?", (new_status, pid))
    audit(g.user["id"], f"product_{new_status}", f"product:{pid}", target["title"])
    flash(f"상품 '{target['title']}' 을(를) {new_status} 처리했습니다.", "success")
    return redirect(url_for("admin.products"))

@bp.route("/products/<int:pid>/delete", methods=("POST",))
@admin_required
def delete_product(pid):
    target = query_one("SELECT * FROM products WHERE id = ?", (pid,))
    if target is None:
        abort(404)
    from products import _delete_image
    _delete_image(target["image_path"])
    execute("DELETE FROM products WHERE id = ?", (pid,))
    audit(g.user["id"], "product_delete", f"product:{pid}", target["title"])
    flash("상품을 삭제했습니다.", "info")
    return redirect(url_for("admin.products"))

@bp.route("/reports")
@admin_required
def reports():
    rows = query_all(
        "SELECT r.*, u.username AS reporter_name "
        "FROM reports r JOIN users u ON u.id = r.reporter_id "
        "ORDER BY (r.status='open') DESC, r.created_at DESC"
    )
    return render_template("admin/reports.html", reports=rows)

@bp.route("/reports/<int:rid>/resolve", methods=("POST",))
@admin_required
def resolve_report(rid):
    target = query_one("SELECT * FROM reports WHERE id = ?", (rid,))
    if target is None:
        abort(404)
    execute(
        "UPDATE reports SET status='resolved', handled_by=? WHERE id = ?",
        (g.user["id"], rid),
    )
    audit(g.user["id"], "report_resolve", f"report:{rid}", "")
    flash("신고를 처리 완료로 표시했습니다.", "success")
    return redirect(url_for("admin.reports"))

@bp.route("/audit")
@admin_required
def audit_log():
    rows = query_all(
        "SELECT a.*, u.username AS actor_name "
        "FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id "
        "ORDER BY a.created_at DESC LIMIT 200"
    )
    return render_template("admin/audit.html", logs=rows)
