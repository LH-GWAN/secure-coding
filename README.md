# Tiny Second-hand Shopping Platform

Flask + SQLite 로 구현

## 필요 사항

 Python 3.10 이상 (별도 DB 서버 불필요 — SQLite 내장)

## 설치 및 실행

### 1) 필요 설치 라이브러리
```
pip install -r requirements.txt
```

### 2) 실행
```
python3 app.py
```

브라우저에서 http://127.0.0.1:5000 접속

- 최초 실행 시 `instance/app.sqlite3` 가 자동 생성되고 스키마·관리자 계정이 초기화
- 관리자 계정은 보고서에서 확인
