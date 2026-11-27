"""In-memory stand-ins for the DynamoDB, SES, S3 and SSM clients.

They implement only what the handlers call, including the conditional writes
that make approvals single-use, so the tests exercise the real logic offline.
"""

from __future__ import annotations

import io

from resume_request.common import Settings

SECRET = b"test-signing-key-not-a-real-secret"
PARAM_NAME = "/resume-request/hmac-key"


class ConditionFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


def settings(**overrides) -> Settings:
    base = dict(
        table_name="requests",
        bucket="resume-bucket",
        resume_key="resume/r.pdf",
        secret_param=PARAM_NAME,
        sender="resume@example.dev",
        reply_to="owner@example.com",
        owner_email="owner@example.com",
        allowed_origin="https://example.dev",
        approve_url="https://api.example/approve",
        link_ttl_seconds=7 * 86400,
        record_ttl_days=30,
        daily_cap=3,
    )
    base.update(overrides)
    return Settings(**base)


def _n(item, name):
    return int(item[name]["N"]) if name in item else None


class FakeDynamo:
    def __init__(self):
        self.items: dict[str, dict] = {}

    def put_item(self, TableName, Item, ConditionExpression=None, ExpressionAttributeNames=None,
                 ExpressionAttributeValues=None):
        pk = Item["pk"]["S"]
        existing = self.items.get(pk)
        if ConditionExpression == "attribute_not_exists(pk)" and existing:
            raise ConditionFailed()
        if ConditionExpression and "#ttl < :now" in ConditionExpression and existing:
            if _n(existing, "ttl") >= int(ExpressionAttributeValues[":now"]["N"]):
                raise ConditionFailed()
        self.items[pk] = dict(Item)

    def get_item(self, TableName, Key, ConsistentRead=False):
        item = self.items.get(Key["pk"]["S"])
        return {"Item": dict(item)} if item else {}

    def delete_item(self, TableName, Key):
        self.items.pop(Key["pk"]["S"], None)

    def update_item(self, TableName, Key, UpdateExpression, ConditionExpression=None,
                    ExpressionAttributeNames=None, ExpressionAttributeValues=None):
        pk = Key["pk"]["S"]
        item = self.items.setdefault(pk, {"pk": {"S": pk}})
        vals = ExpressionAttributeValues or {}
        if UpdateExpression.startswith("ADD n"):
            n = _n(item, "n") or 0
            if n >= int(vals[":cap"]["N"]):
                raise ConditionFailed()
            item["n"] = {"N": str(n + 1)}
            item["ttl"] = vals[":ttl"]
            return
        if ConditionExpression == "#s = :pending" and item.get("status", {}).get("S") != "PENDING":
            raise ConditionFailed()
        for part in UpdateExpression.removeprefix("SET ").split(","):
            name, value = (p.strip() for p in part.split("="))
            name = (ExpressionAttributeNames or {}).get(name, name)
            item[name] = vals[value]


class FakeSES:
    def __init__(self, fail=False):
        self.sent: list[dict] = []
        self.fail = fail

    def send_email(self, **kwargs):
        if self.fail:
            raise RuntimeError("SES down")
        self.sent.append(kwargs)
        return {"MessageId": "m-1"}


class FakeS3:
    def __init__(self, data=b"%PDF-1.7 fake"):
        self.data = data

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.data)}


class FakeSSM:
    def get_parameter(self, Name, WithDecryption):
        assert WithDecryption
        return {"Parameter": {"Value": SECRET.decode()}}
