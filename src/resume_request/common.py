"""Shared pieces: settings, input validation, signed approve links, AWS clients.

Nothing in this module logs a requester's name, email or company. Logs carry the
request id only, so CloudWatch never holds personal data.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import time
from dataclasses import dataclass
from functools import cache

# Field limits. Generous for real names and companies, tight enough to block junk.
MAX_NAME = 100
MAX_COMPANY = 120
MAX_EMAIL = 254

# One plain address: local@domain.tld, no spaces, quotes, angle brackets or commas.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,63}$")
# Letters (any language), digits, spaces and common name/company punctuation.
TEXT_RE = re.compile(r"^[\w .,'&()/\-]+$", re.UNICODE)
# Things that make a "name" look like spam: links and markup.
SPAMMY_RE = re.compile(r"(?i)https?://|www\.|<|>")


@dataclass(frozen=True)
class Settings:
    table_name: str
    bucket: str
    resume_key: str
    secret_param: str
    sender: str
    reply_to: str
    owner_email: str
    allowed_origin: str
    approve_url: str
    link_ttl_seconds: int
    record_ttl_days: int
    daily_cap: int

    @staticmethod
    def from_env() -> Settings:
        env = os.environ
        return Settings(
            table_name=env["TABLE_NAME"],
            bucket=env.get("RESUME_BUCKET", ""),
            resume_key=env.get("RESUME_KEY", ""),
            secret_param=env["SECRET_PARAM"],
            sender=env["SENDER"],
            reply_to=env["REPLY_TO"],
            owner_email=env["OWNER_EMAIL"],
            allowed_origin=env.get("ALLOWED_ORIGIN", ""),
            approve_url=env.get("APPROVE_URL", ""),
            link_ttl_seconds=int(env.get("LINK_TTL_SECONDS", str(7 * 24 * 3600))),
            record_ttl_days=int(env.get("RECORD_TTL_DAYS", "30")),
            daily_cap=int(env.get("DAILY_CAP", "20")),
        )


# ---------------------------------------------------------------- validation


class InvalidInput(ValueError):
    """The form data failed a check; the message is safe to show the requester."""


def clean_text(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise InvalidInput(f"{field} is required.")
    text = " ".join(value.split())  # collapse whitespace, drop newlines
    if not text:
        raise InvalidInput(f"{field} is required.")
    if len(text) > limit:
        raise InvalidInput(f"{field} is too long.")
    if SPAMMY_RE.search(text) or not TEXT_RE.match(text):
        raise InvalidInput(f"{field} has characters that aren't allowed.")
    return text


def clean_email(value: object) -> str:
    if not isinstance(value, str):
        raise InvalidInput("Email is required.")
    email = value.strip()
    if len(email) > MAX_EMAIL or not EMAIL_RE.match(email):
        raise InvalidInput("Please enter a valid email address.")
    return email


def validate_request(body: dict) -> dict:
    """Return the cleaned form fields, or raise InvalidInput."""
    return {
        "name": clean_text(body.get("name"), "Name", MAX_NAME),
        "email": clean_email(body.get("email")),
        "company": clean_text(body.get("company"), "Company", MAX_COMPANY),
    }


# ---------------------------------------------------------- signed approve links


def sign(secret: bytes, request_id: str, expires: int) -> str:
    msg = f"{request_id}.{expires}".encode()
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify(secret: bytes, request_id: str, expires: str, sig: str, now: float | None = None) -> bool:
    """True only for an untampered, unexpired link. Constant-time comparison."""
    if not (request_id and expires and sig) or not expires.isdigit():
        return False
    if int(expires) < (now if now is not None else time.time()):
        return False
    return hmac.compare_digest(sign(secret, request_id, int(expires)), sig)


# ----------------------------------------------------------------- HTTP helpers


def json_response(status: int, payload: dict, origin: str = "") -> dict:
    headers = {"content-type": "application/json"}
    if origin:
        headers["access-control-allow-origin"] = origin
    return {"statusCode": status, "headers": headers, "body": json.dumps(payload)}


def html_page(status: int, title: str, body_html: str) -> dict:
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{html.escape(title)}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}}
button{{font-size:1rem;padding:.6rem 1.2rem;cursor:pointer}}dt{{font-weight:600}}</style>
</head><body><h1>{html.escape(title)}</h1>{body_html}</body></html>"""
    return {
        "statusCode": status,
        "headers": {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
            "referrer-policy": "no-referrer",
            "x-frame-options": "DENY",
        },
        "body": page,
    }


def event_body(event: dict) -> str:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", errors="replace")
    return body


def header(event: dict, name: str) -> str:
    return (event.get("headers") or {}).get(name.lower(), "")


# ------------------------------------------------------------------ AWS access


@cache
def client(service: str):
    import boto3  # in the Lambda runtime; imported lazily so tests don't need AWS

    return boto3.client(service)


_secret_cache: dict[str, bytes] = {}


def get_secret(param_name: str, ssm=None) -> bytes:
    """Read the HMAC key from SSM Parameter Store (SecureString), cached per container."""
    if param_name not in _secret_cache:
        ssm = ssm or client("ssm")
        resp = ssm.get_parameter(Name=param_name, WithDecryption=True)
        _secret_cache[param_name] = resp["Parameter"]["Value"].encode()
    return _secret_cache[param_name]
