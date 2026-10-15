import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("KEY_DB", APP_DIR / "keys.db"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "abbas@741")
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "plain")  # plain or json

app = FastAPI(title="Key Validation API", version="1.0.0")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_value TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL DEFAULT '',
            device_id TEXT NOT NULL DEFAULT '',
            expires_at TEXT,
            max_uses INTEGER NOT NULL DEFAULT 0,
            uses INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_seen_at TEXT,
            last_nonce TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_keys_value ON keys(key_value);
        """
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_expiry(value: str | None):
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        # Accept YYYY-MM-DD or an ISO timestamp.
        if len(value) == 10:
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def valid_key(row, device_id: str, nonce: str):
    if row is None or row["revoked"]:
        return False, "invalid"
    expiry = parse_expiry(row["expires_at"])
    if expiry and expiry <= datetime.now(timezone.utc):
        return False, "expired"
    if row["max_uses"] and row["uses"] >= row["max_uses"]:
        return False, "limit"
    bound = row["device_id"]
    if bound and bound != device_id:
        return False, "device_mismatch"
    if not device_id or not nonce:
        return False, "missing_fields"
    return True, "ok"


def response(ok: bool, reason: str, key: str, device_id: str):
    # The APK contains the marker `accessOk=%s`; plain mode deliberately returns
    # the compact legacy-compatible form. JSON mode is useful for new clients.
    if RESPONSE_MODE == "json":
        return JSONResponse({"accessOk": ok, "key": key, "device_id": device_id, "reason": reason})
    return PlainTextResponse(f"accessOk={'true' if ok else 'false'}")


@app.get("/", response_class=PlainTextResponse)
@app.get("/rapidcore/lite/kingUjjwal.php", response_class=PlainTextResponse)
def validate(
    key: str = Query(default=""),
    device_id: str = Query(default=""),
    nonce: str = Query(default=""),
):
    conn = db()
    row = conn.execute("SELECT * FROM keys WHERE key_value = ?", (key,)).fetchone()
    ok, reason = valid_key(row, device_id, nonce)
    if ok:
        conn.execute(
            "UPDATE keys SET uses = uses + 1, last_seen_at = ?, last_nonce = ?, device_id = CASE WHEN device_id = '' THEN ? ELSE device_id END WHERE id = ?",
            (now_iso(), nonce, device_id, row["id"]),
        )
        conn.commit()
    conn.close()
    return response(ok, reason, key, device_id)


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "key-validation", "time": now_iso()}


def require_admin(x_admin_token: str | None):
    if not x_admin_token or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="admin authentication required")


def admin_token_from(request: Request, x_admin_token: str | None):
    token = x_admin_token or request.query_params.get("token")
    require_admin(token)


@app.get("/admin/api/keys")
def list_keys(request: Request, x_admin_token: str | None = Header(default=None)):
    admin_token_from(request, x_admin_token)
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM keys ORDER BY id DESC")]
    conn.close()
    return rows


@app.post("/admin/api/keys")
async def create_key(request: Request, x_admin_token: str | None = Header(default=None)):
    admin_token_from(request, x_admin_token)
    data = await request.json()
    key = str(data.get("key") or secrets.token_urlsafe(18)).strip()
    label = str(data.get("label") or "").strip()
    device_id = str(data.get("device_id") or "").strip()
    expires_at = str(data.get("expires_at") or "").strip() or None
    max_uses = int(data.get("max_uses") or 0)
    if not key:
        raise HTTPException(400, "key is required")
    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO keys(key_value,label,device_id,expires_at,max_uses,created_at) VALUES(?,?,?,?,?,?)",
            (key, label, device_id, expires_at, max_uses, now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(409, "key already exists")
    row = dict(conn.execute("SELECT * FROM keys WHERE id = ?", (cur.lastrowid,)).fetchone())
    conn.close()
    return row


@app.post("/admin/api/keys/{key_id}/revoke")
def revoke_key(key_id: int, request: Request, x_admin_token: str | None = Header(default=None)):
    admin_token_from(request, x_admin_token)
    conn = db()
    cur = conn.execute("UPDATE keys SET revoked = 1 WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    if not cur.rowcount:
        raise HTTPException(404, "key not found")
    return {"ok": True}


@app.delete("/admin/api/keys/{key_id}")
def delete_key(key_id: int, request: Request, x_admin_token: str | None = Header(default=None)):
    admin_token_from(request, x_admin_token)
    conn = db()
    cur = conn.execute("DELETE FROM keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    if not cur.rowcount:
        raise HTTPException(404, "key not found")
    return {"ok": True}


ADMIN_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Key Admin</title>
<style>body{font-family:system-ui;margin:0;background:#f4f6f8;color:#17202a}.wrap{max-width:1100px;margin:30px auto;padding:0 18px}.card{background:white;border-radius:12px;padding:18px;margin:14px 0;box-shadow:0 2px 12px #0001}input,button{padding:10px;border:1px solid #ccd3da;border-radius:7px;margin:4px}button{cursor:pointer;background:#1455d9;color:white;border:0}.danger{background:#c62828}.muted{color:#667}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;padding:9px;border-bottom:1px solid #e5e7eb;font-size:14px}.pill{padding:3px 7px;border-radius:10px;background:#dff5e1}.off{background:#ffe0e0}</style></head>
<body><div class="wrap"><h1>Key Validation Admin</h1><p class="muted">Manage keys for the compatible validation API.</p>
<div class="card"><input id="token" type="password" placeholder="Admin token" style="width:240px"><button onclick="load()">Load keys</button></div>
<div class="card"><h3>Create key</h3><input id="key" placeholder="Key (blank = generate)"><input id="label" placeholder="Label"><input id="device" placeholder="Device ID (optional)"><input id="expiry" type="datetime-local"><input id="uses" type="number" min="0" value="0" placeholder="Max uses"><button onclick="createKey()">Create</button></div>
<div class="card"><table class="table"><thead><tr><th>Key</th><th>Label</th><th>Device</th><th>Expiry</th><th>Uses</th><th>Status</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></div>
<script>const $=id=>document.getElementById(id);function hdr(){return {'Content-Type':'application/json','X-Admin-Token':$('token').value}}async function load(){let r=await fetch('/admin/api/keys',{headers:hdr()});if(!r.ok)return alert('Unauthorized or server error');let a=await r.json();$('rows').innerHTML=a.map(x=>`<tr><td><code>${x.key_value}</code></td><td>${x.label||''}</td><td>${x.device_id||'auto-bind'}</td><td>${x.expires_at||'never'}</td><td>${x.uses}/${x.max_uses||'∞'}</td><td><span class="pill ${x.revoked?'off':''}">${x.revoked?'revoked':'active'}</span></td><td>${x.revoked?'':`<button class="danger" onclick="revoke(${x.id})">Revoke</button>`}</td></tr>`).join('')}async function createKey(){let r=await fetch('/admin/api/keys',{method:'POST',headers:hdr(),body:JSON.stringify({key:$('key').value,label:$('label').value,device_id:$('device').value,expires_at:$('expiry').value?new Date($('expiry').value).toISOString():null,max_uses:+$('uses').value})});if(!r.ok)return alert(await r.text());$('key').value='';load()}async function revoke(id){if(!confirm('Revoke this key?'))return;await fetch('/admin/api/keys/'+id+'/revoke',{method:'POST',headers:hdr()});load()}</script></body></html>'''


@app.get("/admin", response_class=HTMLResponse)
def admin():
    return HTMLResponse(ADMIN_HTML)
