import hashlib
import hmac
import os
from datetime import datetime
from dotenv import load_dotenv
from flask import request
from db import get_db

load_dotenv()
KEY = os.environ["SECRET_KEY"].encode()
GENESIS = "0" * 64


def _make_hash(prev_hash, user_id, action, details, ip, created_at):
    raw = f"{prev_hash}|{user_id}|{action}|{details}|{ip}|{created_at}"
    return hmac.new(KEY, raw.encode(), hashlib.sha256).hexdigest()


def log_action(user_id, action, details=""):
    try:
        ip = request.remote_addr
    except RuntimeError:
        ip = "local"
    created_at = datetime.now().isoformat(timespec="seconds")

    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    last = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = last["entry_hash"] if last else GENESIS
    entry_hash = _make_hash(prev_hash, user_id, action, details, ip, created_at)
    conn.execute(
        "INSERT INTO audit_log (user_id, action, details, ip, created_at, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, action, details, ip, created_at, prev_hash, entry_hash),
    )
    conn.commit()
    conn.close()


def verify_chain():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    conn.close()

    prev = GENESIS
    for r in rows:
        expected = _make_hash(
            r["prev_hash"], r["user_id"], r["action"], r["details"], r["ip"], r["created_at"]
        )
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return False, r["id"]
        prev = r["entry_hash"]
    return True, None