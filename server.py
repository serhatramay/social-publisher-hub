#!/usr/bin/env python3
import json
import os
import sqlite3
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = BASE_DIR / "social_publisher.db"

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8081"))

PROVIDER_SPECS: dict[str, dict[str, Any]] = {
    "mastodon": {
        "label": "Mastodon",
        "mode": "api",
        "phase": 1,
        "status": "stable",
        "notes": "Instance + access token gerekli",
        "required_config": ["instance", "access_token"],
    },
    "bluesky": {
        "label": "Bluesky",
        "mode": "api",
        "phase": 1,
        "status": "stable",
        "notes": "Identifier (email/handle) + app password gerekli",
        "required_config": ["identifier", "app_password"],
    },
    "facebook": {
        "label": "Facebook Page",
        "mode": "api",
        "phase": 1,
        "status": "stable",
        "notes": "Page ID + page access token gerekli",
        "required_config": ["page_id", "page_access_token"],
    },
    "linkedin": {
        "label": "LinkedIn",
        "mode": "api",
        "phase": 2,
        "status": "beta",
        "notes": "Access token + author URN gerekli",
        "required_config": ["access_token", "author_urn"],
    },
    "pinterest": {
        "label": "Pinterest",
        "mode": "api",
        "phase": 2,
        "status": "beta",
        "notes": "Board ID + access token gerekli",
        "required_config": ["board_id", "access_token"],
    },
    "instagram": {
        "label": "Instagram",
        "mode": "api",
        "phase": 3,
        "status": "beta",
        "notes": "Business account + Graph token (image_url zorunlu)",
        "required_config": ["ig_user_id", "access_token"],
        "requires_image": True,
    },
    "reddit": {
        "label": "Reddit",
        "mode": "api",
        "phase": 3,
        "status": "beta",
        "notes": "OAuth app + refresh token gerekli",
        "required_config": ["client_id", "client_secret", "refresh_token", "subreddit"],
    },
    "tiktok": {
        "label": "TikTok",
        "mode": "api",
        "phase": 4,
        "status": "placeholder",
        "notes": "Content Posting API onayi gerekli (placeholder)",
        "required_config": ["access_token", "open_id", "video_url"],
    },
    "tumblr": {
        "label": "Tumblr",
        "mode": "api",
        "phase": 4,
        "status": "placeholder",
        "notes": "OAuth 1.0a imza akisi gerekli (placeholder)",
        "required_config": ["consumer_key", "consumer_secret", "token", "token_secret", "blog_identifier"],
    },
    "digg": {
        "label": "Digg",
        "mode": "manual",
        "phase": 5,
        "status": "manual",
        "notes": "Resmi guncel post API yok, manuel/share fallback",
        "required_config": [],
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            mode TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS provider_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_key TEXT UNIQUE NOT NULL,
            config_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            text_body TEXT,
            image_url TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            provider_key TEXT NOT NULL,
            status TEXT NOT NULL,
            remote_id TEXT,
            response_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        );
        """
    )

    now = now_iso()
    for key, spec in PROVIDER_SPECS.items():
        cur.execute(
            """
            INSERT OR IGNORE INTO providers(key, label, enabled, mode, notes, created_at, updated_at)
            VALUES (?, ?, 1, ?, ?, ?, ?)
            """,
            (key, spec["label"], spec["mode"], spec["notes"], now, now),
        )

    conn.commit()
    conn.close()


def parse_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_static(path: str) -> Optional[Tuple[bytes, str]]:
    safe = path.lstrip("/")
    target = (STATIC_DIR / safe).resolve()
    if not str(target).startswith(str(STATIC_DIR.resolve())):
        return None
    if not target.exists() or not target.is_file():
        return None

    ctype = "text/plain; charset=utf-8"
    if target.suffix == ".html":
        ctype = "text/html; charset=utf-8"
    elif target.suffix == ".css":
        ctype = "text/css; charset=utf-8"
    elif target.suffix == ".js":
        ctype = "application/javascript; charset=utf-8"

    return target.read_bytes(), ctype


def db_list_providers() -> list[dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT key, label, enabled, mode, notes, updated_at FROM providers ORDER BY label"
    ).fetchall()

    configs = {
        row["provider_key"]: json.loads(row["config_json"])
        for row in conn.execute("SELECT provider_key, config_json FROM provider_configs").fetchall()
    }
    conn.close()

    out = []
    for row in rows:
        cfg = configs.get(row["key"], {})
        spec = PROVIDER_SPECS.get(row["key"], {})
        validation = validate_provider_config(row["key"], cfg)
        out.append(
            {
                "key": row["key"],
                "label": row["label"],
                "enabled": bool(row["enabled"]),
                "mode": row["mode"],
                "notes": row["notes"],
                "phase": spec.get("phase", 9),
                "status": spec.get("status", "unknown"),
                "required_config": spec.get("required_config", []),
                "configured": bool(cfg),
                "runtime_ready": validation["ok"],
                "missing_config": validation["missing_config"],
                "config_preview": sorted(list(cfg.keys())),
                "updated_at": row["updated_at"],
            }
        )
    return sorted(out, key=lambda x: (x["phase"], x["label"]))


def db_set_provider_config(provider_key: str, config: dict[str, Any]) -> None:
    conn = get_conn()
    now = now_iso()
    conn.execute(
        """
        INSERT INTO provider_configs(provider_key, config_json, updated_at)
        VALUES(?, ?, ?)
        ON CONFLICT(provider_key)
        DO UPDATE SET config_json=excluded.config_json, updated_at=excluded.updated_at
        """,
        (provider_key, json.dumps(config), now),
    )
    conn.execute(
        "UPDATE providers SET updated_at=? WHERE key=?",
        (now, provider_key),
    )
    conn.commit()
    conn.close()


def normalize_provider_config(provider_key: str, config: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, str):
            out[key] = value.strip()
        else:
            out[key] = value

    if provider_key == "bluesky":
        identifier = str(out.get("identifier", "")).strip()
        if identifier.startswith("@"):
            identifier = identifier[1:]
        out["identifier"] = identifier
    if provider_key == "mastodon":
        instance = str(out.get("instance", "")).strip()
        if instance and not instance.startswith("http://") and not instance.startswith("https://"):
            instance = "https://" + instance
        out["instance"] = instance.rstrip("/")
    return out


def validate_provider_config(provider_key: str, config: dict[str, Any]) -> dict[str, Any]:
    spec = PROVIDER_SPECS.get(provider_key, {})
    required = spec.get("required_config", [])
    missing: list[str] = []
    for key in required:
        value = config.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(key)
    return {"ok": len(missing) == 0, "missing_config": missing}


def validate_publish_request(provider_key: str, post: dict[str, str]) -> dict[str, Any]:
    spec = PROVIDER_SPECS.get(provider_key, {})
    issues: list[str] = []
    if spec.get("requires_image") and not post.get("image_url"):
        issues.append("image_url gerekli")
    if provider_key == "bluesky":
        text = f"{post.get('title', '')}\n{post.get('url', '')}"
        if len(text) > 300:
            issues.append("Bluesky için başlık+URL 300 karakteri aşıyor")
    return {"ok": len(issues) == 0, "issues": issues}


def db_get_provider_config(provider_key: str) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute(
        "SELECT config_json FROM provider_configs WHERE provider_key=?",
        (provider_key,),
    ).fetchone()
    conn.close()
    if not row:
        return {}
    return json.loads(row["config_json"])


def db_save_post(title: str, url: str, text_body: str, image_url: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO posts(title, url, text_body, image_url, created_at) VALUES (?, ?, ?, ?, ?)",
        (title, url, text_body, image_url, now_iso()),
    )
    post_id = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return post_id


def db_log_delivery(post_id: int, provider_key: str, status: str, remote_id: str, response: dict[str, Any]) -> None:
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO deliveries(post_id, provider_key, status, remote_id, response_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (post_id, provider_key, status, remote_id, json.dumps(response), now_iso()),
    )
    conn.commit()
    conn.close()


def db_recent_deliveries(limit: int = 100) -> list[dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT d.id, d.post_id, d.provider_key, d.status, d.remote_id, d.response_json, d.created_at,
               p.title, p.url
        FROM deliveries d
        JOIN posts p ON p.id=d.post_id
        ORDER BY d.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    out = []
    for row in rows:
        out.append(
            {
                "id": row["id"],
                "post_id": row["post_id"],
                "provider_key": row["provider_key"],
                "status": row["status"],
                "remote_id": row["remote_id"],
                "response": json.loads(row["response_json"] or "{}"),
                "created_at": row["created_at"],
                "title": row["title"],
                "url": row["url"],
            }
        )
    return out


def http_json(method: str, url: str, payload: dict[str, Any], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", **headers}
    req = Request(url, data=data, headers=req_headers, method=method)
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            if not raw:
                return resp.status, {}
            return resp.status, json.loads(raw)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        detail: dict[str, Any] = {"error": str(exc), "body": raw}
        try:
            detail["json"] = json.loads(raw)
        except Exception:
            pass
        return exc.code, detail
    except URLError as exc:
        return 599, {"error": str(exc)}


def http_get_json(url: str, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            if not raw:
                return resp.status, {}
            return resp.status, json.loads(raw)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        detail: dict[str, Any] = {"error": str(exc), "body": raw}
        try:
            detail["json"] = json.loads(raw)
        except Exception:
            pass
        return exc.code, detail
    except URLError as exc:
        return 599, {"error": str(exc)}


def http_form(method: str, url: str, form: dict[str, str], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    encoded = urlencode(form).encode("utf-8")
    req_headers = {"Content-Type": "application/x-www-form-urlencoded", **headers}
    req = Request(url, data=encoded, headers=req_headers, method=method)
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            if not raw:
                return resp.status, {}
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        return exc.code, {"error": str(exc), "body": raw}
    except URLError as exc:
        return 599, {"error": str(exc)}


def post_mastodon(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    instance = config.get("instance", "").strip().rstrip("/")
    token = config.get("access_token", "").strip()
    if not instance or not token:
        return "failed", "", {"error": "instance ve access_token zorunlu"}

    payload = {
        "status": f"{post['title']}\n\n{post['url']}\n\n{post['text_body'] or ''}".strip(),
    }
    status, resp = http_json(
        "POST",
        f"{instance}/api/v1/statuses",
        payload,
        {"Authorization": f"Bearer {token}"},
    )
    if 200 <= status < 300:
        return "ok", str(resp.get("id", "")), resp
    return "failed", "", {"status": status, "detail": resp}


def post_bluesky(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    identifier = config.get("identifier", "").strip()
    app_password = config.get("app_password", "").strip()
    if not identifier or not app_password:
        return "failed", "", {"error": "identifier ve app_password zorunlu"}

    login_status, login_resp = http_json(
        "POST",
        "https://bsky.social/xrpc/com.atproto.server.createSession",
        {"identifier": identifier, "password": app_password},
        {},
    )
    if not (200 <= login_status < 300):
        return "failed", "", {"step": "login", "status": login_status, "detail": login_resp}

    access_jwt = login_resp.get("accessJwt", "")
    did = login_resp.get("did", "")
    text = f"{post['title']}\n{post['url']}"
    create_payload = {
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text[:300],
            "createdAt": now_iso(),
        },
    }

    create_status, create_resp = http_json(
        "POST",
        "https://bsky.social/xrpc/com.atproto.repo.createRecord",
        create_payload,
        {"Authorization": f"Bearer {access_jwt}"},
    )
    if 200 <= create_status < 300:
        return "ok", str(create_resp.get("uri", "")), create_resp
    return "failed", "", {"step": "createRecord", "status": create_status, "detail": create_resp}


def test_provider(provider_key: str, config: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if provider_key == "mastodon":
        instance = str(config.get("instance", "")).strip().rstrip("/")
        token = str(config.get("access_token", "")).strip()
        if not instance or not token:
            return "failed", {"error": "instance ve access_token zorunlu"}
        status, resp = http_get_json(
            f"{instance}/api/v1/accounts/verify_credentials",
            {"Authorization": f"Bearer {token}"},
        )
        if 200 <= status < 300:
            return "ok", {"account": resp.get("acct", ""), "display_name": resp.get("display_name", "")}
        return "failed", {"step": "verify_credentials", "status": status, "detail": resp}
    if provider_key == "bluesky":
        identifier = str(config.get("identifier", "")).strip()
        app_password = str(config.get("app_password", "")).strip()
        if not identifier or not app_password:
            return "failed", {"error": "identifier ve app_password zorunlu"}
        status, resp = http_json(
            "POST",
            "https://bsky.social/xrpc/com.atproto.server.createSession",
            {"identifier": identifier, "password": app_password},
            {},
        )
        if 200 <= status < 300:
            return "ok", {"did": resp.get("did", "")}
        return "failed", {"step": "login", "status": status, "detail": resp}
    if provider_key == "facebook":
        token = str(config.get("page_access_token", "")).strip()
        page_id = str(config.get("page_id", "")).strip()
        if not token or not page_id:
            return "failed", {"error": "page_id ve page_access_token zorunlu"}
        query = urlencode({"fields": "id,name", "access_token": token})
        status, resp = http_get_json(
            f"https://graph.facebook.com/v21.0/{page_id}?{query}",
            {},
        )
        if 200 <= status < 300:
            return "ok", {"page_id": resp.get("id", ""), "page_name": resp.get("name", "")}
        return "failed", {"step": "page_lookup", "status": status, "detail": resp}
    return "failed", {"error": "Bu provider için test endpoint'i henüz yok"}


def post_linkedin(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    token = config.get("access_token", "").strip()
    author = config.get("author_urn", "").strip()
    if not token or not author:
        return "failed", "", {"error": "access_token ve author_urn zorunlu"}

    payload = {
        "author": author,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {
                    "text": f"{post['title']}\n{post['url']}"
                },
                "shareMediaCategory": "ARTICLE",
                "media": [
                    {
                        "status": "READY",
                        "originalUrl": post["url"],
                        "title": {"text": post["title"]},
                    }
                ],
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }

    status, resp = http_json(
        "POST",
        "https://api.linkedin.com/v2/ugcPosts",
        payload,
        {
            "Authorization": f"Bearer {token}",
            "X-Restli-Protocol-Version": "2.0.0",
        },
    )
    if 200 <= status < 300:
        return "ok", str(resp.get("id", "")), resp
    return "failed", "", {"status": status, "detail": resp}


def post_facebook(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    token = config.get("page_access_token", "").strip()
    page_id = config.get("page_id", "").strip()
    if not token or not page_id:
        return "failed", "", {"error": "page_id ve page_access_token zorunlu"}

    msg = f"{post['title']}\n\n{post['text_body'] or ''}".strip()
    form = {
        "message": msg,
        "link": post["url"],
        "access_token": token,
    }
    status, resp = http_form("POST", f"https://graph.facebook.com/v21.0/{page_id}/feed", form, {})
    if 200 <= status < 300:
        return "ok", str(resp.get("id", "")), resp
    return "failed", "", {"status": status, "detail": resp}


def post_pinterest(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    token = config.get("access_token", "").strip()
    board_id = config.get("board_id", "").strip()
    if not token or not board_id:
        return "failed", "", {"error": "board_id ve access_token zorunlu"}

    payload = {
        "board_id": board_id,
        "title": post["title"][:100],
        "description": (post["text_body"] or "")[:500],
        "link": post["url"],
    }
    if post.get("image_url"):
        payload["media_source"] = {"source_type": "image_url", "url": post["image_url"]}

    status, resp = http_json(
        "POST",
        "https://api.pinterest.com/v5/pins",
        payload,
        {"Authorization": f"Bearer {token}"},
    )
    if 200 <= status < 300:
        return "ok", str(resp.get("id", "")), resp
    return "failed", "", {"status": status, "detail": resp}


def post_reddit(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    client_id = config.get("client_id", "").strip()
    client_secret = config.get("client_secret", "").strip()
    refresh_token = config.get("refresh_token", "").strip()
    user_agent = config.get("user_agent", "SocialPublisher/1.0").strip()
    subreddit = config.get("subreddit", "").strip()
    if not all([client_id, client_secret, refresh_token, subreddit]):
        return "failed", "", {"error": "client_id, client_secret, refresh_token, subreddit zorunlu"}

    import base64

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")
    token_form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    token_status, token_resp = http_form(
        "POST",
        "https://www.reddit.com/api/v1/access_token",
        token_form,
        {
            "Authorization": f"Basic {basic}",
            "User-Agent": user_agent,
        },
    )
    if not (200 <= token_status < 300):
        return "failed", "", {"step": "token", "status": token_status, "detail": token_resp}

    access_token = token_resp.get("access_token", "")
    submit_form = {
        "sr": subreddit,
        "kind": "link",
        "title": post["title"][:300],
        "url": post["url"],
        "resubmit": "true",
        "api_type": "json",
    }
    submit_status, submit_resp = http_form(
        "POST",
        "https://oauth.reddit.com/api/submit",
        submit_form,
        {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": user_agent,
        },
    )
    if 200 <= submit_status < 300:
        return "ok", "", submit_resp
    return "failed", "", {"step": "submit", "status": submit_status, "detail": submit_resp}


def post_instagram(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    token = config.get("access_token", "").strip()
    ig_user_id = config.get("ig_user_id", "").strip()
    if not token or not ig_user_id:
        return "failed", "", {"error": "ig_user_id ve access_token zorunlu"}
    if not post.get("image_url"):
        return "failed", "", {"error": "Instagram icin image_url gerekli"}

    create_form = {
        "image_url": post["image_url"],
        "caption": f"{post['title']}\n{post['url']}",
        "access_token": token,
    }
    create_status, create_resp = http_form(
        "POST",
        f"https://graph.facebook.com/v21.0/{ig_user_id}/media",
        create_form,
        {},
    )
    if not (200 <= create_status < 300):
        return "failed", "", {"step": "create_media", "status": create_status, "detail": create_resp}

    creation_id = create_resp.get("id", "")
    publish_form = {
        "creation_id": creation_id,
        "access_token": token,
    }
    pub_status, pub_resp = http_form(
        "POST",
        f"https://graph.facebook.com/v21.0/{ig_user_id}/media_publish",
        publish_form,
        {},
    )
    if 200 <= pub_status < 300:
        return "ok", str(pub_resp.get("id", "")), pub_resp
    return "failed", "", {"step": "media_publish", "status": pub_status, "detail": pub_resp}


def post_tumblr(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    return "failed", "", {
        "error": "Tumblr API OAuth 1.0a imza gerektiriyor. Bu MVP'de imza akisi eklenmedi.",
        "required": ["consumer_key", "consumer_secret", "token", "token_secret", "blog_identifier"],
    }


def post_tiktok(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    return "failed", "", {
        "error": "TikTok Content Posting API hesap onayi ve video upload akisi gerektirir. Bu MVP'de placeholder.",
        "required": ["access_token", "open_id", "video_url"],
    }


def post_digg(config: dict[str, Any], post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    share = f"https://digg.com/submit?url={post['url']}"
    return "failed", "", {
        "error": "Digg icin resmi guncel otomatik post API bulunmuyor.",
        "manual_share_url": share,
    }


def publish_to_provider(provider_key: str, post: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    config = db_get_provider_config(provider_key)
    handlers = {
        "mastodon": post_mastodon,
        "bluesky": post_bluesky,
        "linkedin": post_linkedin,
        "facebook": post_facebook,
        "pinterest": post_pinterest,
        "reddit": post_reddit,
        "instagram": post_instagram,
        "tumblr": post_tumblr,
        "tiktok": post_tiktok,
        "digg": post_digg,
    }
    if provider_key not in handlers:
        return "failed", "", {"error": f"Bilinmeyen provider: {provider_key}"}
    return handlers[provider_key](config, post)


class AppHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/health":
            return json_response(self, {"ok": True, "time": now_iso()})

        if parsed.path == "/api/providers":
            return json_response(self, {"items": db_list_providers()})

        if parsed.path == "/api/deliveries":
            return json_response(self, {"items": db_recent_deliveries()})

        if parsed.path == "/api/provider-config":
            qs = parse_qs(parsed.query)
            provider_key = (qs.get("provider", [""])[0] or "").strip()
            if not provider_key:
                return json_response(self, {"error": "provider param zorunlu"}, status=400)
            return json_response(self, {"provider_key": provider_key, "config": db_get_provider_config(provider_key)})

        if parsed.path == "/api/provider-config-template":
            qs = parse_qs(parsed.query)
            provider_key = (qs.get("provider", [""])[0] or "").strip()
            templates = {
                "mastodon": {"instance": "https://mastodon.social", "access_token": ""},
                "bluesky": {"identifier": "mail@example.com", "app_password": ""},
                "linkedin": {"access_token": "", "author_urn": "urn:li:person:xxxx"},
                "facebook": {"page_id": "", "page_access_token": ""},
                "pinterest": {"board_id": "", "access_token": ""},
                "reddit": {
                    "client_id": "",
                    "client_secret": "",
                    "refresh_token": "",
                    "subreddit": "",
                    "user_agent": "SocialPublisher/1.0",
                },
                "instagram": {"ig_user_id": "", "access_token": ""},
                "tumblr": {
                    "consumer_key": "",
                    "consumer_secret": "",
                    "token": "",
                    "token_secret": "",
                    "blog_identifier": "example.tumblr.com",
                },
                "tiktok": {"access_token": "", "open_id": "", "video_url": ""},
                "digg": {},
            }
            return json_response(self, {"provider_key": provider_key, "template": templates.get(provider_key, {})})

        if parsed.path == "/" or parsed.path == "":
            data = read_static("index.html")
            if data:
                body, ctype = data
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

        data = read_static(parsed.path)
        if data:
            body, ctype = data
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        json_response(self, {"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/provider-config":
            try:
                body = parse_json_body(self)
                provider_key = str(body.get("provider_key", "")).strip()
                config = body.get("config", {})
                if not provider_key:
                    return json_response(self, {"error": "provider_key zorunlu"}, status=400)
                if not isinstance(config, dict):
                    return json_response(self, {"error": "config obje olmali"}, status=400)
                normalized = normalize_provider_config(provider_key, config)
                validation = validate_provider_config(provider_key, normalized)
                if not validation["ok"] and body.get("strict", False):
                    return json_response(
                        self,
                        {"error": "Eksik config alanlari", "missing_config": validation["missing_config"]},
                        status=400,
                    )
                db_set_provider_config(provider_key, normalized)
                return json_response(self, {"ok": True, "validation": validation})
            except Exception as exc:
                return json_response(self, {"error": str(exc)}, status=500)

        if parsed.path == "/api/provider-test":
            try:
                body = parse_json_body(self)
                provider_key = str(body.get("provider_key", "")).strip()
                if not provider_key:
                    return json_response(self, {"error": "provider_key zorunlu"}, status=400)
                config = db_get_provider_config(provider_key)
                validation = validate_provider_config(provider_key, config)
                if not validation["ok"]:
                    return json_response(
                        self,
                        {
                            "provider_key": provider_key,
                            "status": "failed",
                            "detail": {"error": "Eksik config alanlari", "missing_config": validation["missing_config"]},
                        },
                    )
                status, detail = test_provider(provider_key, config)
                return json_response(self, {"provider_key": provider_key, "status": status, "detail": detail})
            except Exception as exc:
                return json_response(self, {"error": str(exc)}, status=500)

        if parsed.path == "/api/publish-validate":
            try:
                body = parse_json_body(self)
                title = str(body.get("title", "")).strip()
                url = str(body.get("url", "")).strip()
                text_body = str(body.get("text_body", "")).strip()
                image_url = str(body.get("image_url", "")).strip()
                providers = body.get("providers", [])
                if not isinstance(providers, list):
                    providers = []
                post_payload = {"title": title, "url": url, "text_body": text_body, "image_url": image_url}

                items = []
                for provider_key in providers:
                    spec = PROVIDER_SPECS.get(provider_key, {})
                    cfg = db_get_provider_config(provider_key)
                    cfg_val = validate_provider_config(provider_key, cfg)
                    post_val = validate_publish_request(provider_key, post_payload)
                    items.append(
                        {
                            "provider_key": provider_key,
                            "phase": spec.get("phase"),
                            "status": spec.get("status"),
                            "config_ok": cfg_val["ok"],
                            "missing_config": cfg_val["missing_config"],
                            "post_ok": post_val["ok"],
                            "post_issues": post_val["issues"],
                        }
                    )
                return json_response(self, {"ok": True, "items": items})
            except Exception as exc:
                return json_response(self, {"error": str(exc)}, status=500)

        if parsed.path == "/api/publish":
            try:
                body = parse_json_body(self)
                title = str(body.get("title", "")).strip()
                url = str(body.get("url", "")).strip()
                text_body = str(body.get("text_body", "")).strip()
                image_url = str(body.get("image_url", "")).strip()
                providers = body.get("providers", [])

                if not title or not url:
                    return json_response(self, {"error": "title ve url zorunlu"}, status=400)
                if not isinstance(providers, list) or not providers:
                    return json_response(self, {"error": "en az bir provider secilmeli"}, status=400)
                if not (url.startswith("http://") or url.startswith("https://")):
                    return json_response(self, {"error": "url http/https ile baslamali"}, status=400)

                validation_errors = []
                for provider_key in providers:
                    spec = PROVIDER_SPECS.get(provider_key, {})
                    cfg = db_get_provider_config(provider_key)
                    cfg_val = validate_provider_config(provider_key, cfg)
                    post_val = validate_publish_request(
                        provider_key,
                        {"title": title, "url": url, "text_body": text_body, "image_url": image_url},
                    )
                    if not cfg_val["ok"] or not post_val["ok"]:
                        validation_errors.append(
                            {
                                "provider_key": provider_key,
                                "phase": spec.get("phase"),
                                "status": spec.get("status"),
                                "missing_config": cfg_val["missing_config"],
                                "post_issues": post_val["issues"],
                            }
                        )
                if validation_errors:
                    return json_response(
                        self,
                        {"error": "Bazi providerlar hazir degil", "validation_errors": validation_errors},
                        status=400,
                    )

                post_id = db_save_post(title, url, text_body, image_url)
                post_payload = {
                    "title": title,
                    "url": url,
                    "text_body": text_body,
                    "image_url": image_url,
                }

                results = []
                for provider_key in providers:
                    status, remote_id, detail = publish_to_provider(provider_key, post_payload)
                    db_log_delivery(post_id, provider_key, status, remote_id, detail)
                    results.append(
                        {
                            "provider_key": provider_key,
                            "status": status,
                            "remote_id": remote_id,
                            "detail": detail,
                        }
                    )

                return json_response(self, {"ok": True, "post_id": post_id, "results": results})
            except Exception as exc:
                return json_response(self, {"error": str(exc)}, status=500)

        return json_response(self, {"error": "Not found"}, status=404)


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print(f"Social Publisher running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
