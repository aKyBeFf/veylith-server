# API Veylith: единственное место, где лежит секретный ключ Supabase.
#
# Сайт и лаунчер его не видят: сайт ходит сюда, а сервис ходит в Supabase.
#
# Маршруты
#   GET  /health                 проверка для Render
#   POST /api/register           регистрация аккаунта (подписки ещё нет)
#   POST /api/login              вход, отдаёт подписанный токен сессии на 7 дней
#   POST /api/profile            профиль по токену: логин, срок подписки, привязан ли ПК
#   POST /api/redeem             активация ключа по токену
#   POST /api/admin/issue-key    выпуск ключа по ADMIN_TOKEN (для вебхука оплаты или вручную)
#
# Переменные окружения (задаются в Render, в git не попадают)
#   SUPABASE_URL, SUPABASE_SECRET_KEY, ADMIN_TOKEN, SESSION_SECRET, ALLOWED_ORIGIN (адрес сайта без слэша), PORT
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 4096
USERNAME = re.compile(r"^[A-Za-z0-9_]{3,24}$")
KEY_FORMAT = re.compile(r"^[A-Z0-9@$#!%^&*]{4}(-[A-Z0-9@$#!%^&*]{4}){11}$")

LIMITS = {
    "/api/register": (5, 600),
    "/api/login": (10, 600),
    "/api/profile": (60, 600),
    "/api/redeem": (10, 600),
    "/api/admin/issue-key": (30, 60),
}
SESSION_SECONDS = 7 * 24 * 3600


def env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"missing environment variable {name}")
    return value


SUPABASE_URL = env("SUPABASE_URL").rstrip("/")
SECRET_KEY = env("SUPABASE_SECRET_KEY")
ADMIN_TOKEN = env("ADMIN_TOKEN")
SESSION_SECRET = env("SESSION_SECRET").encode()
ALLOWED_ORIGIN = env("ALLOWED_ORIGIN").rstrip("/")
PORT = int(os.environ.get("PORT", "8787"))

_hits = defaultdict(deque)
_lock = threading.Lock()


def limited(route, who):
    attempts, window = LIMITS[route]
    now = time.monotonic()
    with _lock:
        q = _hits[(route, who)]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= attempts:
            return True
        q.append(now)
        if len(_hits) > 20000:
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > 3600]:
                del _hits[k]
    return False


def rpc(function, payload):
    headers = {"Content-Type": "application/json", "apikey": SECRET_KEY}
    if SECRET_KEY.startswith("eyJ"):
        headers["Authorization"] = f"Bearer {SECRET_KEY}"
    req = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/rpc/{function}", data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read() or b"null")
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"[supabase] {function} failed: {type(e).__name__}", flush=True)
        return None


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(username):
    payload = b64(json.dumps({"u": username, "e": int(time.time()) + SESSION_SECONDS}).encode())
    return payload + "." + b64(hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest())


def session_user(header):
    if not header.startswith("Bearer ") or header.count(".") != 1:
        return None
    payload, signature = header[7:].split(".")
    good = b64(hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature.encode(), good.encode()):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("u"), str) or data.get("e", 0) < time.time():
        return None
    return data["u"]


def text(value, limit):
    return value if isinstance(value, str) and 0 < len(value) <= limit else None


def register(body):
    user, password = text(body.get("username"), 24), text(body.get("password"), 72)
    if not user or not password or not USERNAME.match(user) or len(password) < 8:
        return 400, {"ok": False, "error": "invalid"}
    return rpc_result("create_account", {"p_user": user, "p_pass": password}, ok_status=201)


def login(body):
    user, password = text(body.get("username"), 24), text(body.get("password"), 72)
    if not user or not password or not USERNAME.match(user):
        return 401, {"ok": False, "error": "bad_credentials"}
    status, result = rpc_result("account_login", {"p_user": user, "p_pass": password})
    if result.get("ok"):
        result = {"ok": True, "username": result["username"], "token": sign(result["username"])}
    return status, result


def profile(body, user):
    status, result = rpc_result("account_info", {"p_user": user})
    if not result.get("ok"):
        return (401, {"ok": False, "error": "unauthorized"}) if result.get("error") == "not_found" else (status, result)
    return 200, {k: result[k] for k in ("ok", "username", "expires_at", "hw_bound", "created_at")}


def redeem(body, user):
    key = text(body.get("key"), 59)
    if not key or not KEY_FORMAT.match(key):
        return 400, {"ok": False, "error": "invalid"}
    return rpc_result("redeem_key_for", {"p_user": user, "p_key": key})


def issue_key(body):
    days = body.get("days")
    note = body.get("note")
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650:
        return 400, {"ok": False, "error": "invalid"}
    if note is not None and (not isinstance(note, str) or len(note) > 200):
        return 400, {"ok": False, "error": "invalid"}
    key = rpc("issue_key", {"p_days": days, "p_note": note})
    if not isinstance(key, str):
        return 502, {"ok": False, "error": "server"}
    return 201, {"ok": True, "key": key}


def rpc_result(function, payload, ok_status=200):
    result = rpc(function, payload)
    if not isinstance(result, dict) or "ok" not in result:
        return 502, {"ok": False, "error": "server"}
    if result["ok"]:
        return ok_status, result
    status = {"taken": 409, "rate_limited": 429, "bad_credentials": 401}.get(result.get("error"), 400)
    return status, {"ok": False, "error": result.get("error", "invalid")}


ROUTES = {
    "/api/register": ("site", register),
    "/api/login": ("site", login),
    "/api/profile": ("session", profile),
    "/api/redeem": ("session", redeem),
    "/api/admin/issue-key": ("admin", issue_key),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "veylith"
    sys_version = ""

    def client(self):
        forwarded = self.headers.get("X-Forwarded-For", "")
        return (forwarded.split(",")[0].strip() or self.client_address[0])[:64]

    def send(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.headers.get("Origin") == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        if self.headers.get("Origin") == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send(200, {"ok": True})
        else:
            self.send(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        route = ROUTES.get(self.path)
        if route is None:
            return self.send(404, {"ok": False, "error": "not_found"})
        access, handler = route

        user = None
        if access == "admin":
            sent = self.headers.get("Authorization", "")
            if not sent.startswith("Bearer ") or not hmac.compare_digest(sent[7:].encode(), ADMIN_TOKEN.encode()):
                return self.send(401, {"ok": False, "error": "unauthorized"})
        else:
            if self.headers.get("Origin") != ALLOWED_ORIGIN:
                return self.send(403, {"ok": False, "error": "forbidden"})
            if access == "session":
                user = session_user(self.headers.get("Authorization", ""))
                if user is None:
                    return self.send(401, {"ok": False, "error": "unauthorized"})

        if limited(self.path, self.client()):
            return self.send(429, {"ok": False, "error": "rate_limited"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            return self.send(413 if length > MAX_BODY else 400, {"ok": False, "error": "invalid"})
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return self.send(400, {"ok": False, "error": "invalid"})
        if not isinstance(body, dict):
            return self.send(400, {"ok": False, "error": "invalid"})

        status, payload = handler(body, user) if access == "session" else handler(body)
        self.send(status, payload)

    def log_message(self, fmt, *args):
        print(f"{self.client()} {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}", flush=True)


if __name__ == "__main__":
    print(f"veylith api on :{PORT}, origin {ALLOWED_ORIGIN}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
