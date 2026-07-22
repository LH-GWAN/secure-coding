import os
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, session, url_for

import db as database
from extensions import socketio
from security import (
    apply_security_headers, generate_csrf_token, validate_csrf,
)

BASE_DIR = Path(__file__).parent

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets_or_dev()),
        DATABASE=str(BASE_DIR / "instance" / "app.sqlite3"),
        UPLOAD_FOLDER=str(BASE_DIR / "uploads"),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", "admin1234!"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.teardown_appcontext(database.close_db)

    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        g.user = None
        if user_id is not None:
            user = database.query_one(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            )
            # 정지/삭제된 계정은 다음 요청부터 세션 즉시 무효화
            if user is None or user["status"] == "suspended":
                session.clear()
                g.user = None
            else:
                g.user = user

    @app.before_request
    def csrf_protect():
        validate_csrf()

    @app.after_request
    def set_headers(response):
        return apply_security_headers(response)

    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    from auth import bp as auth_bp
    from products import bp as products_bp
    from messages import bp as messages_bp
    from chat import bp as chat_bp
    from transfers import bp as transfers_bp
    from reports import bp as reports_bp
    from admin import bp as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(transfers_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)

    @app.route("/")
    def index():
        return redirect(url_for("products.list_products"))

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400,
                               message=str(e.description)), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message="접근 권한이 없습니다."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="페이지를 찾을 수 없습니다."), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413,
                               message="업로드 용량이 너무 큽니다(최대 2MB)."), 413

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Internal error")
        return render_template("error.html", code=500,
                               message="서버 오류가 발생했습니다."), 500

    database.init_db(app)

    socketio.init_app(app)

    return app

def secrets_or_dev():
    import secrets as _s
    return _s.token_hex(32)

app = create_app()

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False,
                 allow_unsafe_werkzeug=True)
