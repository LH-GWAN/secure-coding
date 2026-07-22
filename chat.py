import time
from collections import defaultdict, deque

from flask import Blueprint, render_template, request, session

from db import query_all, execute, query_one
from extensions import socketio
from security import login_required

bp = Blueprint("chat", __name__, url_prefix="/chat")

MAX_CHAT = 500
FEED_LIMIT = 50

RATE_LIMIT = 5
RATE_WINDOW = 10.0
_sent_times = defaultdict(deque)

def _rate_ok(user_id):
    now = time.time()
    dq = _sent_times[user_id]
    while dq and now - dq[0] > RATE_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT:
        return False
    dq.append(now)
    return True

def _current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    user = query_one("SELECT id, username, status FROM users WHERE id = ?", (uid,))
    if user is None or user["status"] == "suspended":
        return None
    return user

@bp.route("/")
@login_required
def room():
    rows = query_all(
        "SELECT c.id, c.content, c.created_at, u.username "
        "FROM chat_messages c JOIN users u ON u.id = c.user_id "
        "ORDER BY c.id DESC LIMIT ?",
        (FEED_LIMIT,),
    )
    return render_template("chat.html", msgs=list(reversed(rows)))

# 소켓 연결 시 로그인 인증 확인 + 매 메시지 검증/rate limit 적용
@socketio.on("connect")
def on_connect():
    if _current_user() is None:
        return False
    return None

@socketio.on("chat_message")
def on_chat_message(data):
    user = _current_user()
    if user is None:
        return

    if not isinstance(data, dict):
        return
    content = data.get("content")
    if not isinstance(content, str):
        return

    content = content.strip()
    if not content or len(content) > MAX_CHAT:
        return

    if not _rate_ok(user["id"]):
        socketio.emit("chat_error", {"message": "메시지를 너무 빠르게 보내고 있습니다."},
                      to=request.sid)
        return

    row_id = execute(
        "INSERT INTO chat_messages (user_id, content) VALUES (?, ?)",
        (user["id"], content),
    )
    msg = query_one(
        "SELECT c.id, c.content, c.created_at, u.username "
        "FROM chat_messages c JOIN users u ON u.id = c.user_id WHERE c.id = ?",
        (row_id,),
    )
    socketio.emit("chat_message", {
        "id": msg["id"], "user": msg["username"],
        "content": msg["content"], "at": msg["created_at"],
    })
