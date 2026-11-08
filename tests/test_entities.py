"""Unit tests for typed entity extraction and fingerprinting.

These are the foundation the origin gate depends on. If emails do not
round-trip through normalize + fingerprint, the pipeline tests cannot pass.
"""

from decimal import InvalidOperation

import pytest

from sluice.detectors.entities import (
    extract_entities,
    fingerprint,
    mask,
    normalize,
    resolve_path,
)


def test_email_normalize_lowercases_and_strips():
    assert normalize("email", "  Bill@Acme-Finance.net ") == "bill@acme-finance.net"


def test_email_fingerprint_is_stable_and_truncated():
    digest = fingerprint("email", "Bill@Acme-Finance.net")
    assert digest == fingerprint("email", "  bill@acme-finance.net")
    assert len(digest) == 16
    assert all(c in "0123456789abcdef" for c in digest)


def test_email_fingerprint_differs_by_kind():
    value = "bill@acme-finance.net"
    assert fingerprint("email", value) != fingerprint("url", f"https://{value}")


def test_email_mask_keeps_domain_hides_local():
    assert mask("email", "bill@acme-finance.net") == "bil***@acme-finance.net"


def test_iban_normalize_strips_spaces_and_uppercases():
    assert normalize("iban", "de89 3704 0044 0532 0130 00") == "DE89370400440532013000"


def test_amount_four_thousand_collides():
    assert normalize("amount", "4,000.00") == "4000"
    assert normalize("amount", "4000") == "4000"
    assert fingerprint("amount", "4,000.00") == fingerprint("amount", "4000")
    assert fingerprint("amount", "4000.00") == fingerprint("amount", "4,000.00")


def test_amount_european_thousands():
    assert normalize("amount", "4.000,00") == "4000"


def test_amount_keeps_cents():
    assert normalize("amount", "12.50") == "12.50"
    assert fingerprint("amount", "12.50") != fingerprint("amount", "12")


def test_empty_amount_raises():
    with pytest.raises(InvalidOperation):
        normalize("amount", "   ")


def test_extract_emails_from_payload_skips_amounts_by_default():
    payload = {
        "text": "Pay bill@acme-finance.net the sum of 4,000.00 at https://pay.acme.test/x"
    }
    found = extract_entities(payload)
    kinds = {kind for kind, _ in found}
    assert "email" in kinds
    assert "url" in kinds
    assert "amount" not in kinds


def test_extract_amounts_opt_in():
    found = extract_entities("Total 4,000.00 please", kinds=["amount"], include_amounts=True)
    assert found == [("amount", "4,000.00")]


def test_extract_from_plain_string():
    assert extract_entities("reach me at Bill@Acme-Finance.net") == [
        ("email", "Bill@Acme-Finance.net")
    ]


def test_extract_dedupes_normalized_duplicates():
    text = "Bill@Acme-Finance.net and bill@acme-finance.net"
    found = extract_entities(text, kinds=["email"])
    assert len(found) == 1


def test_resolve_path_wildcard_and_nested():
    args = {
        "purchase_units": [
            {"payee": {"email_address": "bill@acme-finance.net"}, "amount": {"value": "4000.00"}},
            {"payee": {"email_address": "ops@acme-finance.net"}, "amount": {"value": "12.00"}},
        ]
    }
    emails = resolve_path(args, "purchase_units[].payee.email_address")
    amounts = resolve_path(args, "purchase_units[].amount.value")
    assert emails == ["bill@acme-finance.net", "ops@acme-finance.net"]
    assert amounts == ["4000.00", "12.00"]


def test_resolve_path_plain_key():
    assert resolve_path({"order_id": "ORDER-99"}, "order_id") == ["ORDER-99"]


def test_resolve_path_missing_is_empty():
    assert resolve_path({"x": 1}, "purchase_units[].payee.email_address") == []
    assert resolve_path(None, "order_id") == []
