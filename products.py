import os

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template,
    request, send_from_directory, url_for
)

from db import audit, execute, query_all, query_one
from security import login_required, random_filename, validate_image

bp = Blueprint("products", __name__, url_prefix="/products")

MAX_TITLE = 100
MAX_DESC = 2000
MAX_PRICE = 100_000_000

@bp.route("/")
def list_products():
    q = request.args.get("q", "").strip()
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%") \
                          .replace("_", "\\_") + "%"
        items = query_all(
            "SELECT p.*, u.username AS seller_name "
            "FROM products p JOIN users u ON p.seller_id = u.id "
            "WHERE p.status != 'blocked' "
            "  AND (p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\') "
            "ORDER BY p.created_at DESC",
            (pattern, pattern),
        )
    else:
        items = query_all(
            "SELECT p.*, u.username AS seller_name "
            "FROM products p JOIN users u ON p.seller_id = u.id "
            "WHERE p.status != 'blocked' ORDER BY p.created_at DESC"
        )
    return render_template("products/list.html", items=items, q=q)

@bp.route("/<int:pid>")
def detail(pid):
    item = query_one(
        "SELECT p.*, u.username AS seller_name "
        "FROM products p JOIN users u ON p.seller_id = u.id WHERE p.id = ?",
        (pid,),
    )
    if item is None:
        abort(404)
    if item["status"] == "blocked":
        if g.user is None or (
            g.user["id"] != item["seller_id"] and g.user["role"] != "admin"
        ):
            abort(404)
    return render_template("products/detail.html", item=item)

@bp.route("/new", methods=("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()

        error = _validate_fields(title, description, price_raw)
        if error:
            flash(error, "danger")
            return render_template("products/form.html", mode="new")

        price = int(price_raw)
        image_name = _handle_upload(request.files.get("image"))
        if image_name is False:
            flash("이미지는 png/jpg/gif/webp 형식만 업로드할 수 있습니다.", "danger")
            return render_template("products/form.html", mode="new")

        pid = execute(
            "INSERT INTO products (seller_id, title, description, price, image_path) "
            "VALUES (?, ?, ?, ?, ?)",
            (g.user["id"], title, description, price, image_name),
        )
        flash("상품이 등록되었습니다.", "success")
        return redirect(url_for("products.detail", pid=pid))

    return render_template("products/form.html", mode="new")

@bp.route("/<int:pid>/edit", methods=("GET", "POST"))
@login_required
def edit(pid):
    item = query_one("SELECT * FROM products WHERE id = ?", (pid,))
    if item is None:
        abort(404)
    if item["seller_id"] != g.user["id"]:
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        status = request.form.get("status", item["status"])

        error = _validate_fields(title, description, price_raw)
        if status not in ("available", "sold"):
            error = error or "잘못된 상태 값입니다."
        if error:
            flash(error, "danger")
            return render_template("products/form.html", mode="edit", item=item)

        image_name = item["image_path"]
        new_image = _handle_upload(request.files.get("image"))
        if new_image is False:
            flash("이미지는 png/jpg/gif/webp 형식만 업로드할 수 있습니다.", "danger")
            return render_template("products/form.html", mode="edit", item=item)
        if new_image:
            _delete_image(item["image_path"])
            image_name = new_image

        execute(
            "UPDATE products SET title=?, description=?, price=?, status=?, "
            "image_path=? WHERE id = ?",
            (title, description, int(price_raw), status, image_name, pid),
        )
        flash("상품이 수정되었습니다.", "success")
        return redirect(url_for("products.detail", pid=pid))

    return render_template("products/form.html", mode="edit", item=item)

@bp.route("/<int:pid>/delete", methods=("POST",))
@login_required
def delete(pid):
    item = query_one("SELECT * FROM products WHERE id = ?", (pid,))
    if item is None:
        abort(404)
    if item["seller_id"] != g.user["id"]:
        abort(404)
    _delete_image(item["image_path"])
    execute("DELETE FROM products WHERE id = ?", (pid,))
    flash("상품이 삭제되었습니다.", "info")
    return redirect(url_for("products.list_products"))

@bp.route("/image/<path:filename>")
def image(filename):
    # send_from_directory 가 업로드 폴더 밖 경로 이탈(../)을 차단
    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"], filename, as_attachment=False
    )

def _validate_fields(title, description, price_raw):
    if not title or len(title) > MAX_TITLE:
        return f"제목은 1~{MAX_TITLE}자여야 합니다."
    if len(description) > MAX_DESC:
        return f"설명은 최대 {MAX_DESC}자까지 가능합니다."
    if not price_raw.isdigit():
        return "가격은 0 이상의 정수여야 합니다."
    if int(price_raw) > MAX_PRICE:
        return "가격이 허용 범위를 초과했습니다."
    return None

def _handle_upload(file_storage):
    if not file_storage or file_storage.filename == "":
        return None
    ext = validate_image(file_storage)
    if ext is None:
        return False
    name = random_filename(ext)
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], name)
    file_storage.save(path)
    return name

def _delete_image(name):
    if not name:
        return
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], name)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        current_app.logger.warning("Failed to remove image: %s", name)
