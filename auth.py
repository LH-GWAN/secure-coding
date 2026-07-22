from datetime import datetime, timedelta

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from db import audit, execute, query_one

bp = Blueprint("auth", __name__, url_prefix="/auth")

MAX_FAILED = 5
LOCK_MINUTES = 10
USERNAME_MIN, USERNAME_MAX = 3, 20
PASSWORD_MIN = 8

def _valid_username(u: str) -> bool:
    return (USERNAME_MIN <= len(u) <= USERNAME_MAX
            and all(c.isalnum() or c == "_" for c in u))

@bp.route("/register", methods=("GET", "POST"))
def register():
    if g.user:
        return redirect(url_for("products.list_products"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not _valid_username(username):
            error = "아이디는 3~20자의 영문/숫자/밑줄만 가능합니다."
        elif len(password) < PASSWORD_MIN:
            error = f"비밀번호는 최소 {PASSWORD_MIN}자 이상이어야 합니다."
        elif password != confirm:
            error = "비밀번호 확인이 일치하지 않습니다."
        elif query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
            error = "이미 사용 중인 아이디입니다."

        if error is None:
            uid = execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            audit(uid, "register", f"user:{uid}", username)
            flash("가입이 완료되었습니다. 로그인해 주세요.", "success")
            return redirect(url_for("auth.login"))
        flash(error, "danger")

    return render_template("register.html")

@bp.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("products.list_products"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_one("SELECT * FROM users WHERE username = ?", (username,))

        if user and user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                flash("로그인 시도가 많아 계정이 일시적으로 잠겼습니다. "
                      "잠시 후 다시 시도해 주세요.", "danger")
                return render_template("login.html")

        if user is None or not check_password_hash(user["password_hash"], password):
            if user is not None:
                _register_failure(user)
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
            return render_template("login.html")

        if user["status"] == "suspended":
            flash("정지된 계정입니다. 관리자에게 문의하세요.", "danger")
            return render_template("login.html")

        # 로그인 성공 시 세션 재발급 (세션 고정 공격 방어)
        session.clear()
        session["user_id"] = user["id"]
        execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        audit(user["id"], "login", f"user:{user['id']}", "")

        next_url = request.args.get("next", "")
        if next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("products.list_products"))

    return render_template("login.html")

def _register_failure(user):
    failed = user["failed_logins"] + 1
    if failed >= MAX_FAILED:
        locked = (datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)).isoformat()
        execute(
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
            (failed, locked, user["id"]),
        )
        audit(user["id"], "account_locked", f"user:{user['id']}",
              f"{failed} failed attempts")
    else:
        execute("UPDATE users SET failed_logins = ? WHERE id = ?",
                (failed, user["id"]))

@bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for("auth.login"))

@bp.route("/me", methods=("GET", "POST"))
def settings():
    if g.user is None:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "bio":
            bio = request.form.get("bio", "").strip()
            if len(bio) > 500:
                flash("소개글은 최대 500자까지 가능합니다.", "danger")
            else:
                execute("UPDATE users SET bio = ? WHERE id = ?",
                        (bio, g.user["id"]))
                audit(g.user["id"], "update_bio", f"user:{g.user['id']}", "")
                flash("소개글이 수정되었습니다.", "success")

        elif action == "password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not check_password_hash(g.user["password_hash"], current):
                flash("현재 비밀번호가 올바르지 않습니다.", "danger")
            elif len(new) < PASSWORD_MIN:
                flash(f"새 비밀번호는 최소 {PASSWORD_MIN}자 이상이어야 합니다.", "danger")
            elif new != confirm:
                flash("새 비밀번호 확인이 일치하지 않습니다.", "danger")
            else:
                execute("UPDATE users SET password_hash = ? WHERE id = ?",
                        (generate_password_hash(new), g.user["id"]))
                audit(g.user["id"], "change_password", f"user:{g.user['id']}", "")
                uid = g.user["id"]
                session.clear()
                session["user_id"] = uid
                flash("비밀번호가 변경되었습니다.", "success")

        return redirect(url_for("auth.settings"))

    return render_template("settings.html")

@bp.route("/profile/<int:user_id>")
def profile(user_id):
    from flask import abort

    from db import query_all

    user = query_one(
        "SELECT id, username, bio, created_at, status FROM users WHERE id = ?",
        (user_id,),
    )
    if user is None:
        abort(404)
    items = query_all(
        "SELECT * FROM products WHERE seller_id = ? AND status != 'blocked' "
        "ORDER BY created_at DESC",
        (user_id,),
    )
    return render_template("profile.html", profile_user=user, items=items)
