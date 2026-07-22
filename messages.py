from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, url_for
)

from db import execute, query_all, query_one
from security import login_required

bp = Blueprint("messages", __name__, url_prefix="/messages")

MAX_MSG = 1000

@bp.route("/")
@login_required
def inbox():
    me = g.user["id"]
    partners = query_all(
        "SELECT u.id, u.username, MAX(m.created_at) AS last_at "
        "FROM messages m "
        "JOIN users u ON u.id = CASE WHEN m.sender_id = ? "
        "                            THEN m.receiver_id ELSE m.sender_id END "
        "WHERE m.sender_id = ? OR m.receiver_id = ? "
        "GROUP BY u.id, u.username ORDER BY last_at DESC",
        (me, me, me),
    )
    return render_template("messages/inbox.html", partners=partners)

@bp.route("/with/<int:other_id>", methods=("GET", "POST"))
@login_required
def thread(other_id):
    me = g.user["id"]
    if other_id == me:
        abort(404)
    other = query_one(
        "SELECT id, username, status FROM users WHERE id = ?", (other_id,)
    )
    if other is None or other["status"] == "suspended":
        abort(404)

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("메시지를 입력하세요.", "warning")
        elif len(content) > MAX_MSG:
            flash(f"메시지는 최대 {MAX_MSG}자까지 가능합니다.", "danger")
        else:
            execute(
                "INSERT INTO messages (sender_id, receiver_id, content) "
                "VALUES (?, ?, ?)",
                (me, other_id, content),
            )
        return redirect(url_for("messages.thread", other_id=other_id))

    msgs = query_all(
        "SELECT * FROM messages "
        "WHERE (sender_id = ? AND receiver_id = ?) "
        "   OR (sender_id = ? AND receiver_id = ?) "
        "ORDER BY created_at ASC",
        (me, other_id, other_id, me),
    )
    return render_template("messages/thread.html", other=other, msgs=msgs)
