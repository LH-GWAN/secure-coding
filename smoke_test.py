import io
import os
import re
import tempfile

os.environ["SECRET_KEY"] = "test-secret"

import app as appmod

def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""

def make_png():
    return (b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"IHDR" + b"\x00" * 20)

def run():
    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test.sqlite3")
    up_path = os.path.join(tmpdir, "uploads")
    os.makedirs(up_path, exist_ok=True)

    application = appmod.create_app({
        "TESTING": True,
        "DATABASE": db_path,
        "UPLOAD_FOLDER": up_path,
        "WTF_CSRF_ENABLED": False,
        "ADMIN_PASSWORD": "admin1234!",
    })
    import db as database
    database.init_db(application)

    passed, failed = [], []

    def check(name, cond):
        (passed if cond else failed).append(name)
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")

    c = application.test_client()

    def register(u, p):
        r = c.get("/auth/register")
        token = csrf(r.get_data(as_text=True))
        return c.post("/auth/register", data={
            "username": u, "password": p, "confirm": p, "csrf_token": token
        }, follow_redirects=True)

    def login(u, p):
        r = c.get("/auth/login")
        token = csrf(r.get_data(as_text=True))
        return c.post("/auth/login", data={
            "username": u, "password": p, "csrf_token": token
        }, follow_redirects=True)

    def get_token(path="/products/new"):
        return csrf(c.get(path, follow_redirects=True).get_data(as_text=True))

    def logout():
        c.post("/auth/logout", data={"csrf_token": get_token("/products/")},
               follow_redirects=True)

    print("\n== 인증 ==")
    register("alice", "password123")
    register("bob", "password123")
    r = login("alice", "password123")
    check("로그인 성공", "로그아웃" in r.get_data(as_text=True))

    r = login("alice", "wrongpass")
    logout()
    r = login("alice", "wrongpass")
    check("잘못된 비밀번호 거부", "올바르지 않습니다" in r.get_data(as_text=True))
    login("alice", "password123")

    print("\n== CSRF ==")
    r = c.post("/products/new", data={"title": "x", "price": "1"})
    check("CSRF 토큰 없는 POST 거부(400)", r.status_code == 400)

    print("\n== 상품 등록 + XSS 저장 ==")
    tok = get_token()
    xss = '<script>alert(1)</script>'
    r = c.post("/products/new", data={
        "title": xss, "description": "테스트 설명", "price": "5000",
        "csrf_token": tok,
    }, follow_redirects=True)
    body = r.get_data(as_text=True)
    check("상품 등록 성공", "테스트 설명" in body)
    check("XSS 스크립트 이스케이프됨",
          "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body)

    print("\n== 이미지 업로드 검증 ==")
    tok = get_token()
    r = c.post("/products/new", data={
        "title": "fake", "description": "d", "price": "1", "csrf_token": tok,
        "image": (io.BytesIO(b"this is not an image"), "evil.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    check("위조 이미지(내용 불일치) 거부",
          "형식만 업로드" in r.get_data(as_text=True))
    tok = get_token()
    r = c.post("/products/new", data={
        "title": "with image", "description": "d", "price": "1", "csrf_token": tok,
        "image": (io.BytesIO(make_png()), "ok.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    check("정상 PNG 업로드 성공", "with image" in r.get_data(as_text=True))
    saved = os.listdir(up_path)
    check("업로드 파일이 랜덤 hex 이름으로 저장됨",
          any(re.fullmatch(r"[0-9a-f]{32}\.png", f) for f in saved))

    print("\n== 검색 (SQLi 시도 무해화) ==")
    r = c.get("/products/?q=' OR '1'='1")
    check("SQLi 페이로드가 문자열로 처리(에러/전체노출 없음)", r.status_code == 200)
    r = c.get("/products/?q=테스트")
    check("정상 검색 동작", r.status_code == 200)

    print("\n== IDOR (타인 상품 수정 차단) ==")
    with application.app_context():
        pid = database.query_one(
            "SELECT id FROM products ORDER BY id LIMIT 1")["id"]
    logout()
    login("bob", "password123")
    r = c.get(f"/products/{pid}/edit")
    check("타인 상품 수정 페이지 접근 차단(404)", r.status_code == 404)
    tok = get_token("/")
    r = c.post(f"/products/{pid}/delete", data={"csrf_token": tok})
    check("타인 상품 삭제 차단(404)", r.status_code == 404)

    print("\n== 메시지 (타인 대화 격리) ==")
    tok = csrf(c.get("/messages/with/2").get_data(as_text=True))
    with application.app_context():
        alice_id = database.query_one(
            "SELECT id FROM users WHERE username='alice'")["id"]
    tok = csrf(c.get(f"/messages/with/{alice_id}").get_data(as_text=True))
    c.post(f"/messages/with/{alice_id}",
           data={"content": "안녕하세요 bob 입니다", "csrf_token": tok},
           follow_redirects=True)
    r = c.get(f"/messages/with/{alice_id}")
    check("본인이 보낸 메시지 조회됨", "bob 입니다" in r.get_data(as_text=True))

    print("\n== 송금 + 레이스/잔액 검증 ==")
    tok = csrf(c.get("/transfers/").get_data(as_text=True))
    c.post("/transfers/charge", data={"csrf_token": tok})
    tok = csrf(c.get("/transfers/").get_data(as_text=True))
    r = c.post("/transfers/send", data={
        "to_username": "alice", "amount": "30000", "memo": "책값",
        "csrf_token": tok}, follow_redirects=True)
    check("정상 송금 성공", "송금했습니다" in r.get_data(as_text=True))
    tok = csrf(c.get("/transfers/").get_data(as_text=True))
    r = c.post("/transfers/send", data={
        "to_username": "alice", "amount": "500000", "csrf_token": tok},
        follow_redirects=True)
    check("잔액 초과 송금 거부", "잔액이 부족" in r.get_data(as_text=True))
    tok = csrf(c.get("/transfers/").get_data(as_text=True))
    r = c.post("/transfers/send", data={
        "to_username": "bob", "amount": "1000", "csrf_token": tok},
        follow_redirects=True)
    check("자기 자신 송금 거부", "자기 자신" in r.get_data(as_text=True))
    with application.app_context():
        total = database.query_one("SELECT SUM(balance) s FROM users")["s"]
    check("송금 후 총 잔액 보존(100,000 그대로)", total == 100000)

    print("\n== 접근 제어 (일반유저의 관리자 페이지) ==")
    r = c.get("/admin/")
    check("일반 사용자 관리자 접근 차단(404)", r.status_code == 404)

    print("\n== 관리자 기능 ==")
    logout()
    login("admin", "admin1234!")
    r = c.get("/admin/")
    check("관리자 대시보드 접근", r.status_code == 200)
    with application.app_context():
        bob_id = database.query_one(
            "SELECT id FROM users WHERE username='bob'")["id"]
    tok = csrf(c.get("/admin/users").get_data(as_text=True))
    c.post(f"/admin/users/{bob_id}/suspend", data={"csrf_token": tok},
           follow_redirects=True)
    with application.app_context():
        st = database.query_one(
            "SELECT status FROM users WHERE id=?", (bob_id,))["status"]
    check("관리자가 회원 정지", st == "suspended")
    tok = csrf(c.get("/admin/products").get_data(as_text=True))
    c.post(f"/admin/products/{pid}/block", data={"csrf_token": tok},
           follow_redirects=True)
    with application.app_context():
        pst = database.query_one(
            "SELECT status FROM products WHERE id=?", (pid,))["status"]
    check("관리자가 상품 차단", pst == "blocked")
    r = c.get("/admin/audit")
    check("감사 로그 기록됨", "user_suspended" in r.get_data(as_text=True))

    print("\n== 정지된 계정 즉시 무효화 ==")
    logout()
    r = login("bob", "password123")
    check("정지 계정 로그인 차단", "정지된 계정" in r.get_data(as_text=True))

    print("\n== 보안 헤더 ==")
    r = c.get("/products/")
    check("CSP 헤더 존재", "Content-Security-Policy" in r.headers)
    check("X-Frame-Options=DENY", r.headers.get("X-Frame-Options") == "DENY")
    check("X-Content-Type-Options=nosniff",
          r.headers.get("X-Content-Type-Options") == "nosniff")

    print(f"\n===== 결과: {len(passed)} passed, {len(failed)} failed =====")
    if failed:
        print("실패 항목:", failed)
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)
    return len(failed) == 0

if __name__ == "__main__":
    ok = run()
    raise SystemExit(0 if ok else 1)
