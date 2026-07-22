import functools
import secrets

from flask import (
    abort, current_app, flash, g, redirect, request, session, url_for
)

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

# 모든 POST 요청의 토큰을 상수시간 비교하여 위조 요청을 차단
def validate_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        real = session.get("csrf_token", "")
        if not real or not secrets.compare_digest(sent, real):
            abort(400, description="CSRF 토큰이 유효하지 않습니다.")

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        if g.user["role"] != "admin":
            abort(404)
        return view(*args, **kwargs)
    return wrapped

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
}

def _sniff(head: bytes):
    for sig, kind in _MAGIC.items():
        if head.startswith(sig):
            return kind
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None

# 확장자 화이트리스트 + 매직바이트로 실제 형식 검증 (위장 업로드 차단)
def validate_image(file_storage):
    if not file_storage or file_storage.filename == "":
        return None

    ext = file_storage.filename.rsplit(".", 1)[-1].lower() \
        if "." in file_storage.filename else ""
    if ext not in ALLOWED_EXT:
        return None

    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    kind = _sniff(head)
    if kind is None:
        return None

    return "jpg" if kind == "jpg" else kind

def random_filename(ext: str) -> str:
    return f"{secrets.token_hex(16)}.{ext}"

def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response
