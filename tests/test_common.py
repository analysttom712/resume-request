import pytest

from resume_request.common import InvalidInput, sign, validate_request, verify

KEY = b"k" * 32


def good(**overrides):
    body = {"name": "Ana López", "email": "ana@recruit.example", "company": "Acme & Co."}
    body.update(overrides)
    return body


def test_valid_request_is_cleaned():
    out = validate_request(good(name="  Ana   López \n"))
    assert out == {"name": "Ana López", "email": "ana@recruit.example", "company": "Acme & Co."}


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"name": None},
        {"name": "x" * 101},
        {"name": "Visit https://spam.example"},
        {"name": "<script>"},
        {"company": "www.spam.example"},
        {"email": "not-an-email"},
        {"email": "a@b.example, c@d.example"},
        {"email": "a@b.example\nBcc: x@y.example"},
        {"email": "a" * 250 + "@b.example"},
    ],
)
def test_bad_input_is_rejected(overrides):
    with pytest.raises(InvalidInput):
        validate_request(good(**overrides))


def test_signature_round_trip():
    sig = sign(KEY, "abc123", 2_000)
    assert verify(KEY, "abc123", "2000", sig, now=1_000)


def test_forged_or_altered_links_fail():
    sig = sign(KEY, "abc123", 2_000)
    assert not verify(KEY, "abc124", "2000", sig, now=1_000)  # other request
    assert not verify(KEY, "abc123", "3000", sig, now=1_000)  # extended expiry
    assert not verify(b"x" * 32, "abc123", "2000", sig, now=1_000)  # wrong key
    assert not verify(KEY, "abc123", "2000", "", now=1_000)
    assert not verify(KEY, "abc123", "soon", sig, now=1_000)


def test_expired_link_fails():
    sig = sign(KEY, "abc123", 2_000)
    assert not verify(KEY, "abc123", "2000", sig, now=2_001)
