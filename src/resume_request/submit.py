"""POST /request: a recruiter asks for the resume; the owner gets an Approve link.

Abuse controls, cheapest first: API Gateway throttling (template.yaml), an Origin
check, a honeypot field, strict input validation, a per-address cooldown so one
address can't flood the owner's inbox, and a daily cap on owner emails.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from resume_request.common import (
    InvalidInput,
    Settings,
    client,
    event_body,
    get_secret,
    header,
    json_response,
    sign,
    validate_request,
)

log = logging.getLogger()
log.setLevel(logging.INFO)

HONEYPOT_FIELD = "website"  # hidden on the form; people leave it empty, bots fill it
COOLDOWN_SECONDS = 24 * 3600

OK_MESSAGE = "Thanks! Your request was sent. You'll get the resume by email once it's approved."


@dataclass
class Deps:
    ddb: Any
    ses: Any
    ssm: Any = None


def is_conditional_failure(err: Exception) -> bool:
    code = getattr(err, "response", {}).get("Error", {}).get("Code")
    return code == "ConditionalCheckFailedException"


def handler(event: dict, context: object) -> dict:
    return process(event, Settings.from_env(), Deps(ddb=client("dynamodb"), ses=client("sesv2")))


def process(event: dict, cfg: Settings, deps: Deps, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    origin = cfg.allowed_origin

    # CORS stops browsers on other sites; this also turns away naive scripts.
    if origin and header(event, "origin") != origin:
        return json_response(403, {"ok": False, "message": "Requests are accepted from the website only."})

    try:
        body = json.loads(event_body(event) or "{}")
        if not isinstance(body, dict):
            raise ValueError
    except ValueError:
        return json_response(400, {"ok": False, "message": "Bad request."}, origin)

    if str(body.get(HONEYPOT_FIELD) or "").strip():
        log.info("honeypot filled; request dropped")
        return json_response(200, {"ok": True, "message": OK_MESSAGE}, origin)

    try:
        fields = validate_request(body)
    except InvalidInput as err:
        return json_response(400, {"ok": False, "message": str(err)}, origin)

    # One owner email per address per 24 hours. Repeats look identical to the
    # requester, so the endpoint doesn't reveal what has been asked before.
    email_key = "email#" + hashlib.sha256(fields["email"].lower().encode()).hexdigest()
    try:
        deps.ddb.put_item(
            TableName=cfg.table_name,
            Item={"pk": {"S": email_key}, "ttl": {"N": str(int(now + COOLDOWN_SECONDS))}},
            ConditionExpression="attribute_not_exists(pk) OR #ttl < :now",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":now": {"N": str(int(now))}},
        )
    except Exception as err:
        if is_conditional_failure(err):
            log.info("repeat request within cooldown; no owner email")
            return json_response(200, {"ok": True, "message": OK_MESSAGE}, origin)
        raise

    # Daily cap on owner emails: a backstop on cost and inbox flooding.
    day = datetime.fromtimestamp(now, tz=UTC).strftime("%Y-%m-%d")
    try:
        deps.ddb.update_item(
            TableName=cfg.table_name,
            Key={"pk": {"S": f"counter#{day}"}},
            UpdateExpression="ADD n :one SET #ttl = :ttl",
            ConditionExpression="attribute_not_exists(n) OR n < :cap",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":one": {"N": "1"},
                ":cap": {"N": str(cfg.daily_cap)},
                ":ttl": {"N": str(int(now + 2 * 24 * 3600))},
            },
        )
    except Exception as err:
        if is_conditional_failure(err):
            log.warning("daily cap reached")
            return json_response(
                429,
                {"ok": False, "message": "Too many requests today. Please try again tomorrow or use LinkedIn."},
                origin,
            )
        raise

    request_id = uuid.uuid4().hex
    deps.ddb.put_item(
        TableName=cfg.table_name,
        Item={
            "pk": {"S": f"req#{request_id}"},
            "status": {"S": "PENDING"},
            "name": {"S": fields["name"]},
            "email": {"S": fields["email"]},
            "company": {"S": fields["company"]},
            "created_at": {"N": str(int(now))},
            "ttl": {"N": str(int(now + cfg.record_ttl_days * 24 * 3600))},
        },
        ConditionExpression="attribute_not_exists(pk)",
    )

    expires = int(now + cfg.link_ttl_seconds)
    secret = get_secret(cfg.secret_param, deps.ssm)
    approve_base = cfg.approve_url or f"https://{event['requestContext']['domainName']}/approve"
    link = f"{approve_base}?id={request_id}&exp={expires}&sig={sign(secret, request_id, expires)}"

    text = (
        "New resume request from your website.\n\n"
        f"Name:    {fields['name']}\n"
        f"Company: {fields['company']}\n"
        f"Email:   {fields['email']}\n\n"
        "To send your resume, open this link and press Approve:\n"
        f"{link}\n\n"
        f"The link works once and expires in {cfg.link_ttl_seconds // 86400} days. "
        "Ignore this email to decline; the request is deleted after "
        f"{cfg.record_ttl_days} days.\n"
        "Reply to this email to write to the requester directly.\n"
    )
    try:
        deps.ses.send_email(
            FromEmailAddress=cfg.sender,
            FeedbackForwardingEmailAddress=cfg.reply_to,  # bounces/complaints reach a real inbox
            Destination={"ToAddresses": [cfg.owner_email]},
            ReplyToAddresses=[fields["email"]],
            Content={
                "Simple": {
                    "Subject": {"Data": f"Resume request: {fields['name']} ({fields['company']})"},
                    "Body": {"Text": {"Data": text}},
                }
            },
        )
    except Exception:
        log.exception("owner email failed for request %s", request_id)
        try:  # let the requester try again instead of hitting the cooldown
            deps.ddb.delete_item(TableName=cfg.table_name, Key={"pk": {"S": email_key}})
        except Exception:
            log.exception("could not clear cooldown for request %s", request_id)
        return json_response(
            502,
            {"ok": False, "message": "Sorry, the request couldn't be sent. Please try again later or use LinkedIn."},
            origin,
        )

    log.info("request %s stored and owner notified", request_id)
    return json_response(200, {"ok": True, "message": OK_MESSAGE}, origin)
