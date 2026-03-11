# -*- coding: utf-8 -*-
"""
RocketSourcing 인증 서버
- Flask + SQLite
- 관리자가 ID 배포 방식 (회원가입 없음)
- MAC 주소 기반 PC 사용 대수 제한
- Render.com / Railway 무료 배포 가능
"""

from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
import datetime
from functools import wraps

app = Flask(__name__)

# ===================== 환경 설정 =====================
DB_PATH = os.environ.get("DB_PATH", "users.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "rocketsourcing_admin_2024")  # 배포 시 반드시 변경

# ===================== DB 초기화 =====================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT UNIQUE NOT NULL,
            password_hash   TEXT NOT NULL,
            name            TEXT DEFAULT '',
            expiry_date     TEXT NOT NULL,
            mac_limit       INTEGER DEFAULT 1,
            is_active       INTEGER DEFAULT 1,
            memo            TEXT DEFAULT '',
            created_at      TEXT DEFAULT (datetime('now', 'localtime'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_macs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            mac_address     TEXT NOT NULL,
            registered_at   TEXT DEFAULT (datetime('now', 'localtime')),
            last_seen       TEXT DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, mac_address)
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] 초기화 완료")

# ===================== 유틸 =====================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def require_admin(f):
    """관리자 키 검증 데코레이터"""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Admin-Key", "")
        if key != ADMIN_KEY:
            return jsonify({"success": False, "message": "관리자 권한이 없습니다"}), 403
        return f(*args, **kwargs)
    return decorated

# ===================== 클라이언트 API =====================

@app.route("/api/login", methods=["POST"])
def login():
    """로그인 + MAC 주소 체크"""
    data = request.get_json(silent=True) or {}
    username    = data.get("username", "").strip()
    password    = data.get("password", "")
    mac_address = data.get("mac_address", "").strip().upper()

    if not username or not password:
        return jsonify({"success": False, "message": "아이디와 비밀번호를 입력하세요"}), 400

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # 계정 존재 여부
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "아이디 또는 비밀번호가 틀렸습니다"}), 401

    # 비밀번호 확인
    if user["password_hash"] != hash_password(password):
        conn.close()
        return jsonify({"success": False, "message": "아이디 또는 비밀번호가 틀렸습니다"}), 401

    # 계정 활성화 여부
    if not user["is_active"]:
        conn.close()
        return jsonify({"success": False, "message": "비활성화된 계정입니다. 관리자에게 문의하세요"}), 401

    # 사용기간 만료 여부
    today = datetime.date.today().isoformat()
    if user["expiry_date"] < today:
        conn.close()
        return jsonify({
            "success": False,
            "message": f"사용기간이 만료되었습니다\n만료일: {user['expiry_date']}\n관리자에게 문의하세요"
        }), 401

    # MAC 주소 체크
    if mac_address:
        existing = conn.execute(
            "SELECT mac_address FROM user_macs WHERE user_id = ?", (user["id"],)
        ).fetchall()
        mac_list = [row["mac_address"] for row in existing]

        if mac_address not in mac_list:
            # 새 PC - 허용 대수 초과 확인
            if len(mac_list) >= user["mac_limit"]:
                conn.close()
                return jsonify({
                    "success": False,
                    "message": (
                        f"허용된 PC 대수({user['mac_limit']}대)를 초과했습니다\n"
                        f"현재 등록: {len(mac_list)}대\n"
                        f"관리자에게 PC 허용 대수 증가를 요청하세요"
                    )
                }), 401
            # 새 MAC 등록
            conn.execute(
                "INSERT INTO user_macs (user_id, mac_address) VALUES (?, ?)",
                (user["id"], mac_address)
            )
        else:
            # 기존 PC - last_seen 갱신
            conn.execute(
                "UPDATE user_macs SET last_seen = datetime('now', 'localtime') WHERE user_id = ? AND mac_address = ?",
                (user["id"], mac_address)
            )
        conn.commit()

    conn.close()

    # 만료까지 남은 일수
    expiry = datetime.date.fromisoformat(user["expiry_date"])
    days_left = (expiry - datetime.date.today()).days

    return jsonify({
        "success": True,
        "message": "로그인 성공",
        "user": {
            "username": user["username"],
            "name": user["name"],
            "expiry_date": user["expiry_date"],
            "days_left": days_left,
            "mac_limit": user["mac_limit"]
        }
    })

# ===================== 관리자 API =====================

@app.route("/api/admin/users", methods=["GET"])
@require_admin
def get_users():
    """전체 사용자 목록 조회"""
    conn = get_db()
    users = conn.execute(
        "SELECT * FROM users ORDER BY created_at DESC"
    ).fetchall()

    result = []
    today = datetime.date.today().isoformat()
    for u in users:
        macs = conn.execute(
            "SELECT mac_address, registered_at, last_seen FROM user_macs WHERE user_id = ?",
            (u["id"],)
        ).fetchall()
        result.append({
            "id":           u["id"],
            "username":     u["username"],
            "name":         u["name"],
            "expiry_date":  u["expiry_date"],
            "is_expired":   u["expiry_date"] < today,
            "days_left":    (datetime.date.fromisoformat(u["expiry_date"]) - datetime.date.today()).days,
            "mac_limit":    u["mac_limit"],
            "mac_count":    len(macs),
            "is_active":    bool(u["is_active"]),
            "memo":         u["memo"],
            "created_at":   u["created_at"],
            "macs": [
                {
                    "mac": m["mac_address"],
                    "registered_at": m["registered_at"],
                    "last_seen": m["last_seen"]
                } for m in macs
            ]
        })

    conn.close()
    return jsonify({"success": True, "users": result})


@app.route("/api/admin/users", methods=["POST"])
@require_admin
def create_user():
    """새 사용자 생성"""
    data = request.get_json(silent=True) or {}
    username    = data.get("username", "").strip()
    password    = data.get("password", "")
    name        = data.get("name", "").strip()
    expiry_date = data.get("expiry_date", "")
    mac_limit   = int(data.get("mac_limit", 1))
    memo        = data.get("memo", "").strip()

    if not username or not password or not expiry_date:
        return jsonify({"success": False, "message": "아이디, 비밀번호, 사용기간은 필수입니다"}), 400

    # 날짜 형식 검증
    try:
        datetime.date.fromisoformat(expiry_date)
    except ValueError:
        return jsonify({"success": False, "message": "날짜 형식이 올바르지 않습니다 (YYYY-MM-DD)"}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, name, expiry_date, mac_limit, memo) VALUES (?, ?, ?, ?, ?, ?)",
            (username, hash_password(password), name, expiry_date, mac_limit, memo)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"사용자 '{username}' 생성 완료"})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "message": f"이미 존재하는 아이디입니다: {username}"}), 400


@app.route("/api/admin/users/<username>/expiry", methods=["PUT"])
@require_admin
def update_expiry(username):
    """사용기간 연장"""
    data = request.get_json(silent=True) or {}
    expiry_date = data.get("expiry_date", "")

    try:
        datetime.date.fromisoformat(expiry_date)
    except ValueError:
        return jsonify({"success": False, "message": "날짜 형식이 올바르지 않습니다 (YYYY-MM-DD)"}), 400

    conn = get_db()
    result = conn.execute(
        "UPDATE users SET expiry_date = ? WHERE username = ?", (expiry_date, username)
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404
    return jsonify({"success": True, "message": f"'{username}' 사용기간 → {expiry_date}"})


@app.route("/api/admin/users/<username>/mac_limit", methods=["PUT"])
@require_admin
def update_mac_limit(username):
    """허용 PC 대수 변경"""
    data = request.get_json(silent=True) or {}
    mac_limit = int(data.get("mac_limit", 1))

    if mac_limit < 1:
        return jsonify({"success": False, "message": "최소 1대 이상이어야 합니다"}), 400

    conn = get_db()
    result = conn.execute(
        "UPDATE users SET mac_limit = ? WHERE username = ?", (mac_limit, username)
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404
    return jsonify({"success": True, "message": f"'{username}' 허용 PC → {mac_limit}대"})


@app.route("/api/admin/users/<username>/password", methods=["PUT"])
@require_admin
def reset_password(username):
    """비밀번호 초기화"""
    data = request.get_json(silent=True) or {}
    new_password = data.get("password", "")

    if not new_password:
        return jsonify({"success": False, "message": "새 비밀번호를 입력하세요"}), 400

    conn = get_db()
    result = conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (hash_password(new_password), username)
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404
    return jsonify({"success": True, "message": f"'{username}' 비밀번호 변경 완료"})


@app.route("/api/admin/users/<username>/active", methods=["PUT"])
@require_admin
def update_active(username):
    """계정 활성화/비활성화"""
    data = request.get_json(silent=True) or {}
    is_active = int(bool(data.get("is_active", True)))

    conn = get_db()
    result = conn.execute(
        "UPDATE users SET is_active = ? WHERE username = ?", (is_active, username)
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404
    status = "활성화" if is_active else "비활성화"
    return jsonify({"success": True, "message": f"'{username}' 계정 {status}"})


@app.route("/api/admin/users/<username>/memo", methods=["PUT"])
@require_admin
def update_memo(username):
    """메모 수정"""
    data = request.get_json(silent=True) or {}
    memo = data.get("memo", "")

    conn = get_db()
    conn.execute("UPDATE users SET memo = ? WHERE username = ?", (memo, username))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "메모 저장 완료"})


@app.route("/api/admin/users/<username>/macs/<path:mac_address>", methods=["DELETE"])
@require_admin
def delete_mac(username, mac_address):
    """특정 MAC 주소 삭제 (PC 교체 등)"""
    mac_address = mac_address.upper()
    conn = get_db()
    user = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404

    conn.execute(
        "DELETE FROM user_macs WHERE user_id = ? AND mac_address = ?",
        (user["id"], mac_address)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"MAC 주소 삭제 완료: {mac_address}"})


@app.route("/api/admin/users/<username>/macs", methods=["DELETE"])
@require_admin
def delete_all_macs(username):
    """모든 MAC 주소 초기화"""
    conn = get_db()
    user = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404

    conn.execute("DELETE FROM user_macs WHERE user_id = ?", (user["id"],))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"'{username}' MAC 주소 전체 초기화 완료"})


@app.route("/api/admin/users/<username>", methods=["DELETE"])
@require_admin
def delete_user(username):
    """사용자 삭제"""
    conn = get_db()
    user = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다"}), 404

    conn.execute("DELETE FROM user_macs WHERE user_id = ?", (user["id"],))
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"'{username}' 삭제 완료"})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ===================== 실행 =====================
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
