"""GET/POST /approve: the owner approves a request and the resume goes out.

GET only shows a confirmation page; it never sends anything. Email providers and
security scanners open links in emails automatically, so a GET that sent the
resume could fire without the owner ever clicking. The Approve button POSTs.

Every call re-checks the HMAC signature and expiry. The send is single-use: a
conditional DynamoDB update moves the request from PENDING to SENDING, so a
second click, a replayed link or two clicks at once can't send twice.
"""

from __future__ import annotations

import html
import logging
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any
from urllib.parse import parse_qs

from resume_request.common import Settings, client, event_body, get_secret, html_page, verify

log = logging.getLogger()
log.setLevel(logging.INFO)

ATTACHMENT_NAME = "Thomas-Baynum-Resume.pdf"
SENDER_NAME = "Thomas Baynum"

INVALID = ("Link not valid", "<p>This approve link is invalid or has expired.</p>")


@dataclass
class Deps:
    ddb: Any
    ses: Any
    s3: Any
    ssm: Any = None


def is_conditional_failure(err: Exception) -> bool:
    code = getattr(err, "response", {}).get("Error", {}).get("Code")
    return code == "ConditionalCheckFailedException"


def handler(event: dict, context: object) -> dict:
    deps = Deps(ddb=client("dynamodb"), ses=client("sesv2"), s3=client("s3"))
    return process(event, Settings.from_env(), deps)


def process(event: dict, cfg: Settings, deps: Deps, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    if method == "POST":
        form = {k: v[0] for k, v in parse_qs(event_body(event)).items()}
    else:
        form = event.get("queryStringParameters") or {}
    request_id = str(form.get("id", ""))
    expires = str(form.get("exp", ""))
    sig = str(form.get("sig", ""))

    secret = get_secret(cfg.secret_param, deps.ssm)
    if not request_id.isalnum() or not verify(secret, request_id, expires, sig, now):
        return html_page(403, *INVALID)

    key = {"pk": {"S": f"req#{request_id}"}}
    item = deps.ddb.get_item(TableName=cfg.table_name, Key=key, ConsistentRead=True).get("Item")
    if not item:
        return html_page(404, "Request not found", "<p>This request has expired or was removed.</p>")

    status = item["status"]["S"]
    name, email, company = (item[f]["S"] for f in ("name", "email", "company"))
    details = (
        "<dl>"
        f"<dt>Name</dt><dd>{html.escape(name)}</dd>"
        f"<dt>Company</dt><dd>{html.escape(company)}</dd>"
        f"<dt>Email</dt><dd>{html.escape(email)}</dd>"
        "</dl>"
    )

    if status != "PENDING":
        return html_page(409, "Already handled", f"<p>This request is already {status.lower()}.</p>{details}")

    if method != "POST":
        hidden = "".join(
            f'<input type="hidden" name="{k}" value="{html.escape(v, quote=True)}">'
            for k, v in (("id", request_id), ("exp", expires), ("sig", sig))
        )
        return html_page(
            200,
            "Send your resume?",
            f"{details}<form method=\"post\">{hidden}<button type=\"submit\">Approve and send</button></form>"
            "<p>To decline, close this page. The request is deleted automatically.</p>",
        )

    # Claim the request. Only one caller can win this conditional update.
    try:
        deps.ddb.update_item(
            TableName=cfg.table_name,
            Key=key,
            UpdateExpression="SET #s = :sending, approved_at = :now",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":sending": {"S": "SENDING"},
                ":pending": {"S": "PENDING"},
                ":now": {"N": str(int(now))},
            },
        )
    except Exception as err:
        if is_conditional_failure(err):
            return html_page(409, "Already handled", f"<p>This request was already handled.</p>{details}")
        raise

    try:
        pdf = deps.s3.get_object(Bucket=cfg.bucket, Key=cfg.resume_key)["Body"].read()
        deps.ses.send_email(
            FromEmailAddress=cfg.sender,
            Destination={"ToAddresses": [email]},
            Content={"Raw": {"Data": build_message(cfg, name, email, pdf)}},
        )
    except Exception:
        log.exception("resume send failed for request %s", request_id)
        deps.ddb.update_item(  # put it back so the owner can retry the same link
            TableName=cfg.table_name,
            Key=key,
            UpdateExpression="SET #s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":pending": {"S": "PENDING"}},
        )
        return html_page(502, "Not sent", "<p>The email couldn't be sent. Try the link again in a few minutes.</p>")

    deps.ddb.update_item(
        TableName=cfg.table_name,
        Key=key,
        UpdateExpression="SET #s = :sent, sent_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":sent": {"S": "SENT"}, ":now": {"N": str(int(now))}},
    )
    log.info("resume sent for request %s", request_id)
    return html_page(200, "Sent", f"<p>Your resume is on its way.</p>{details}")


def build_message(cfg: Settings, name: str, to_addr: str, pdf: bytes) -> bytes:
    msg = EmailMessage()
    msg["From"] = formataddr((SENDER_NAME, cfg.sender))
    msg["To"] = to_addr
    msg["Reply-To"] = cfg.reply_to
    msg["Subject"] = "Thomas Baynum's resume"
    first = name.split()[0]
    msg.set_content(
        f"Hi {first},\n\n"
        "Thanks for your interest. My resume is attached.\n\n"
        "Reply to this email to reach me directly.\n\n"
        "Thomas Baynum\n"
        "https://thomasbaynum.dev\n"
    )
    msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=ATTACHMENT_NAME)
    return msg.as_bytes()
