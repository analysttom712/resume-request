"""End-to-end flow against in-memory fakes: request -> owner email -> approve -> resume."""

import json
import re
from email import message_from_bytes
from urllib.parse import parse_qs, urlencode, urlparse

from fakes import FakeDynamo, FakeS3, FakeSES, FakeSSM, settings

from resume_request import approve, submit

NOW = 1_800_000_000
CFG = settings()


def submit_event(body: dict, origin="https://example.dev"):
    return {
        "headers": {"origin": origin, "content-type": "application/json"},
        "body": json.dumps(body),
        "requestContext": {"domainName": "api.example", "http": {"method": "POST"}},
    }


def form(**overrides):
    body = {"name": "Ana López", "email": "ana@recruit.example", "company": "Acme"}
    body.update(overrides)
    return body


def run_submit(ddb, ses, body=None, origin="https://example.dev", now=NOW, cfg=CFG):
    deps = submit.Deps(ddb=ddb, ses=ses, ssm=FakeSSM())
    return submit.process(submit_event(body or form(), origin), cfg, deps, now=now)


def approve_link(ses: FakeSES) -> dict:
    text = ses.sent[-1]["Content"]["Simple"]["Body"]["Text"]["Data"]
    url = re.search(r"https://\S+", text).group(0)
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def run_approve(ddb, ses, params, method="GET", now=NOW + 60, s3=None):
    deps = approve.Deps(ddb=ddb, ses=ses, s3=s3 or FakeS3(), ssm=FakeSSM())
    event = {"requestContext": {"http": {"method": method}}}
    if method == "GET":
        event["queryStringParameters"] = params
    else:
        event["body"] = urlencode(params)
    return approve.process(event, CFG, deps, now=now)


def requests_in(ddb):
    return [v for k, v in ddb.items.items() if k.startswith("req#")]


def test_happy_path_sends_resume_once():
    ddb, ses = FakeDynamo(), FakeSES()
    resp = run_submit(ddb, ses)
    assert resp["statusCode"] == 200
    assert resp["headers"]["access-control-allow-origin"] == "https://example.dev"

    owner_mail = ses.sent[0]
    assert owner_mail["Destination"] == {"ToAddresses": ["owner@example.com"]}
    assert owner_mail["ReplyToAddresses"] == ["ana@recruit.example"]
    [req] = requests_in(ddb)
    assert req["status"]["S"] == "PENDING"
    assert int(req["ttl"]["N"]) == NOW + 30 * 86400  # deleted by DynamoDB TTL after 30 days

    params = approve_link(ses)
    page = run_approve(ddb, ses, params, "GET")
    assert page["statusCode"] == 200 and "Approve and send" in page["body"]
    assert len(ses.sent) == 1  # GET alone never sends

    done = run_approve(ddb, ses, params, "POST")
    assert done["statusCode"] == 200
    assert requests_in(ddb)[0]["status"]["S"] == "SENT"
    raw = ses.sent[1]["Content"]["Raw"]["Data"]
    msg = message_from_bytes(raw)
    assert msg["To"] == "ana@recruit.example"
    assert msg["Reply-To"] == "owner@example.com"
    [att] = [p for p in msg.walk() if p.get_filename()]
    assert att.get_filename() == "Thomas-Baynum-Resume.pdf"
    assert att.get_payload(decode=True) == b"%PDF-1.7 fake"


def test_reused_link_is_refused():
    ddb, ses = FakeDynamo(), FakeSES()
    run_submit(ddb, ses)
    params = approve_link(ses)
    run_approve(ddb, ses, params, "POST")
    again = run_approve(ddb, ses, params, "POST")
    assert again["statusCode"] == 409
    assert len(ses.sent) == 2  # owner email + one resume, no second resume


def test_forged_link_is_refused():
    ddb, ses = FakeDynamo(), FakeSES()
    run_submit(ddb, ses)
    params = approve_link(ses)
    for bad in (
        {**params, "sig": "A" * 43},
        {**params, "exp": str(int(params["exp"]) + 86400)},
        {**params, "id": "0" * 32},
        {"id": params["id"]},
    ):
        resp = run_approve(ddb, ses, bad, "POST")
        assert resp["statusCode"] == 403
    assert len(ses.sent) == 1


def test_expired_link_is_refused():
    ddb, ses = FakeDynamo(), FakeSES()
    run_submit(ddb, ses)
    params = approve_link(ses)
    resp = run_approve(ddb, ses, params, "POST", now=NOW + 8 * 86400)
    assert resp["statusCode"] == 403


def test_failed_send_can_be_retried():
    ddb, ses = FakeDynamo(), FakeSES()
    run_submit(ddb, ses)
    params = approve_link(ses)
    ses.fail = True
    assert run_approve(ddb, ses, params, "POST")["statusCode"] == 502
    assert requests_in(ddb)[0]["status"]["S"] == "PENDING"
    ses.fail = False
    assert run_approve(ddb, ses, params, "POST")["statusCode"] == 200


def test_honeypot_is_silently_dropped():
    ddb, ses = FakeDynamo(), FakeSES()
    resp = run_submit(ddb, ses, form(website="http://bot.example"))
    assert resp["statusCode"] == 200
    assert ses.sent == [] and ddb.items == {}


def test_wrong_origin_is_refused():
    ddb, ses = FakeDynamo(), FakeSES()
    assert run_submit(ddb, ses, origin="https://evil.example")["statusCode"] == 403
    assert ses.sent == []


def test_invalid_input_is_refused():
    ddb, ses = FakeDynamo(), FakeSES()
    resp = run_submit(ddb, ses, form(email="nope"))
    assert resp["statusCode"] == 400
    assert ses.sent == []


def test_same_address_notifies_owner_once_per_day():
    ddb, ses = FakeDynamo(), FakeSES()
    run_submit(ddb, ses)
    second = run_submit(ddb, ses, form(email="ANA@recruit.example"), now=NOW + 60)
    assert second["statusCode"] == 200
    assert len(ses.sent) == 1
    run_submit(ddb, ses, now=NOW + 86400 + 1)
    assert len(ses.sent) == 2


def test_daily_cap_returns_429():
    ddb, ses = FakeDynamo(), FakeSES()
    for i in range(3):
        assert run_submit(ddb, ses, form(email=f"r{i}@recruit.example"))["statusCode"] == 200
    capped = run_submit(ddb, ses, form(email="r9@recruit.example"))
    assert capped["statusCode"] == 429
    assert len(ses.sent) == 3


def test_owner_email_failure_clears_cooldown():
    ddb, ses = FakeDynamo(), FakeSES(fail=True)
    assert run_submit(ddb, ses)["statusCode"] == 502
    ses.fail = False
    assert run_submit(ddb, ses, now=NOW + 60)["statusCode"] == 200
