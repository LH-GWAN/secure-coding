import os
import re
import tempfile

os.environ["SECRET_KEY"] = "test-secret"
import app as appmod
import db as database

def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""

def run():
    tmp = tempfile.mkdtemp()
    application = appmod.create_app({
        "TESTING": True,
        "DATABASE": os.path.join(tmp, "t.sqlite3"),
        "UPLOAD_FOLDER": os.path.join(tmp, "up"),
        "ADMIN_PASSWORD": "admin1234!",
    })
    os.makedirs(os.path.join(tmp, "up"), exist_ok=True)
    database.init_db(application)

    passed, failed = [], []

    def check(name, cond):
        (passed if cond else failed).append(name)
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")

    def client():
        return application.test_client()

    def token(c, path):
        return csrf(c.get(path, follow_redirects=True).get_data(as_text=True))

    def register(c, u, p="password123"):
        c.post("/auth/register", data={
            "username": u, "password": p, "confirm": p,
            "csrf_token": token(c, "/auth/register")}, follow_redirects=True)

    def login(c, u, p="password123"):
        return c.post("/auth/login", data={
            "username": u, "password": p,
            "csrf_token": token(c, "/auth/login")}, follow_redirects=True)

    admin_c = client()
    register(admin_c, "alice")
    register(admin_c, "bob")
    for name in ("rep1", "rep2", "rep3"):
        register(admin_c, name)
    register(admin_c, "victim")
    login(admin_c, "alice")

    print("\n== 전체 채팅 (실시간 Socket.IO) ==")
    from extensions import socketio as sio
    sc = sio.test_client(application, flask_test_client=admin_c)
    check("인증된 소켓 연결됨", sc.is_connected())
    sc.get_received()
    sc.emit("chat_message", {"content": "안녕하세요 전체채팅"})
    recv = sc.get_received()
    got = any(e["name"] == "chat_message" and
              e["args"][0].get("content") == "안녕하세요 전체채팅" for e in recv)
    check("메시지 브로드캐스트 수신", got)
    body = admin_c.get("/chat/").get_data(as_text=True)
    check("전체채팅 메시지 DB 저장/표시", "안녕하세요 전체채팅" in body)
    sc.emit("chat_message", {"content": "<script>alert(2)</script>"})
    sc.get_received()
    body = admin_c.get("/chat/").get_data(as_text=True)
    check("전체채팅 XSS 이스케이프",
          "<script>alert(2)</script>" not in body and "&lt;script&gt;" in body)
    before = admin_c.get("/chat/").get_data(as_text=True).count("class=\"bubble")
    sc.emit("chat_message", {"nope": 1})
    sc.emit("chat_message", "not-a-dict")
    after = admin_c.get("/chat/").get_data(as_text=True).count("class=\"bubble")
    check("잘못된 형식 메시지 무시", before == after)
    sc.get_received()
    for i in range(8):
        sc.emit("chat_message", {"content": "spam %d" % i})
    limited = any(e["name"] == "chat_error" for e in sc.get_received())
    check("Rate limiting 동작(chat_error)", limited)
    anon = client()
    ac = sio.test_client(application, flask_test_client=anon)
    check("미인증 소켓 연결 거부", not ac.is_connected())
    sc.disconnect()

    print("\n== 마이페이지: 소개글 ==")
    t = token(admin_c, "/auth/me")
    admin_c.post("/auth/me", data={"action": "bio", "bio": "안녕하세요 앨리스입니다",
                                   "csrf_token": t}, follow_redirects=True)
    body = admin_c.get("/auth/me").get_data(as_text=True)
    check("소개글 저장/표시", "안녕하세요 앨리스입니다" in body)

    print("\n== 마이페이지: 비밀번호 변경 ==")
    t = token(admin_c, "/auth/me")
    r = admin_c.post("/auth/me", data={
        "action": "password", "current_password": "wrongpass",
        "new_password": "newpass123", "confirm_password": "newpass123",
        "csrf_token": t}, follow_redirects=True)
    check("현재 비밀번호 틀리면 변경 거부", "현재 비밀번호가 올바르지" in r.get_data(as_text=True))
    t = token(admin_c, "/auth/me")
    r = admin_c.post("/auth/me", data={
        "action": "password", "current_password": "password123",
        "new_password": "newpass123", "confirm_password": "newpass123",
        "csrf_token": t}, follow_redirects=True)
    check("올바른 비밀번호로 변경 성공", "비밀번호가 변경되었습니다" in r.get_data(as_text=True))
    admin_c.post("/auth/logout", data={"csrf_token": token(admin_c, "/products/")})
    r = login(admin_c, "alice", "newpass123")
    check("변경된 비밀번호로 로그인", "로그아웃" in r.get_data(as_text=True))

    print("\n== 신고: 사유 직접 입력 ==")
    with application.app_context():
        bob_id = database.query_one(
            "SELECT id FROM users WHERE username='bob'")["id"]
    t = token(admin_c, f"/reports/new?target_type=user&target_id={bob_id}")
    r = admin_c.post("/reports/create", data={
        "target_type": "user", "target_id": str(bob_id), "reason": "",
        "csrf_token": t}, follow_redirects=True)
    check("빈 사유 신고 거부", "사유를 입력" in r.get_data(as_text=True))
    r = admin_c.post("/reports/create", data={
        "target_type": "user", "target_id": str(bob_id), "reason": "사기 의심됨",
        "csrf_token": t}, follow_redirects=True)
    check("사유 포함 신고 접수", "신고가 접수" in r.get_data(as_text=True))
    login_admin = client()
    login(login_admin, "admin", "admin1234!")
    body = login_admin.get("/admin/reports").get_data(as_text=True)
    check("관리자 화면에 신고 사유 노출", "사기 의심됨" in body)

    print("\n== 신고 누적 자동 조치 ==")
    with application.app_context():
        victim_id = database.query_one(
            "SELECT id FROM users WHERE username='victim'")["id"]
    for name in ("rep1", "rep2", "rep3"):
        c = client()
        login(c, name)
        t = token(c, f"/reports/new?target_type=user&target_id={victim_id}")
        c.post("/reports/create", data={
            "target_type": "user", "target_id": str(victim_id),
            "reason": "불량 사용자", "csrf_token": t}, follow_redirects=True)
    with application.app_context():
        st = database.query_one(
            "SELECT status FROM users WHERE id=?", (victim_id,))["status"]
    check("서로 다른 3명 신고 시 유저 자동 휴면", st == "suspended")

    seller = client()
    login(seller, "bob")
    t = token(seller, "/products/new")
    seller.post("/products/new", data={
        "title": "신고대상상품", "description": "d", "price": "1000",
        "csrf_token": t}, follow_redirects=True)
    with application.app_context():
        pid = database.query_one(
            "SELECT id FROM products WHERE title='신고대상상품'")["id"]
    for name in ("rep1", "rep2", "rep3"):
        c = client()
        login(c, name)
        t = token(c, f"/reports/new?target_type=product&target_id={pid}")
        c.post("/reports/create", data={
            "target_type": "product", "target_id": str(pid),
            "reason": "가짜 상품", "csrf_token": t}, follow_redirects=True)
    with application.app_context():
        pst = database.query_one(
            "SELECT status FROM products WHERE id=?", (pid,))["status"]
    check("서로 다른 3명 신고 시 상품 자동 차단", pst == "blocked")

    solo_target = client()
    login(solo_target, "bob")
    t = token(solo_target, "/products/new")
    solo_target.post("/products/new", data={
        "title": "단독신고상품", "description": "d", "price": "1000",
        "csrf_token": t}, follow_redirects=True)
    with application.app_context():
        pid2 = database.query_one(
            "SELECT id FROM products WHERE title='단독신고상품'")["id"]
    spammer = client()
    login(spammer, "rep1")
    for _ in range(3):
        t = token(spammer, f"/reports/new?target_type=product&target_id={pid2}")
        spammer.post("/reports/create", data={
            "target_type": "product", "target_id": str(pid2),
            "reason": "스팸신고", "csrf_token": t}, follow_redirects=True)
    with application.app_context():
        pst2 = database.query_one(
            "SELECT status FROM products WHERE id=?", (pid2,))["status"]
    check("1인 반복 신고로는 자동차단 안 됨(악용 방지)", pst2 != "blocked")

    print(f"\n===== 결과: {len(passed)} passed, {len(failed)} failed =====")
    if failed:
        print("실패:", failed)
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    return len(failed) == 0

if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
