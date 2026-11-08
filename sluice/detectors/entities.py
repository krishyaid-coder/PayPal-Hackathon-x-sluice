"""Typed entity extraction and fingerprinting.

Raw values never leave this module except as a masked display string.
The origin index stores ``fingerprint(kind, value)``, a 16-hex SHA-256
prefix of ``kind:normalized``. Emails are always extracted. Amounts are
opt-in: a bare ``40`` appears in almost every document and would fire
constantly.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from typing import Any

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
URL = re.compile(r"https?://[^\s<>\"']+")
AMOUNT = re.compile(r"(?<![\w.])\d{1,3}(?:[,.]\d{3})*(?:[.,]\d{2})?(?![\w])")

_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": EMAIL,
    "iban": IBAN,
    "url": URL,
    "amount": AMOUNT,
}

# Amounts stay off unless the caller opts in. Emails are the demo entity.
DEFAULT_KINDS: tuple[str, ...] = ("email", "iban", "url")
ALL_KINDS: tuple[str, ...] = ("email", "iban", "url", "amount")


def normalize(kind: str, value: str) -> str:
    text = str(value).strip()
    if kind == "email":
        return text.lower()
    if kind == "iban":
        return text.upper().replace(" ", "")
    if kind == "url":
        return text.rstrip(".,);]>")
    if kind == "amount":
        return _canonical_amount(text)
    return text


def _canonical_amount(value: str) -> str:
    """Render an amount so ``4,000.00`` and ``4000`` share a fingerprint."""
    raw = value.strip()
    if not raw:
        raise InvalidOperation("empty amount")
    if "," in raw and "." in raw:
        if raw.rfind(",") > raw.rfind("."):
            raw = raw.replace(".", "").replace(",", ".")
        else:
            raw = raw.replace(",", "")
    elif "," in raw:
        fractional = raw.rsplit(",", 1)[-1]
        raw = raw.replace(",", ".") if len(fractional) == 2 else raw.replace(",", "")
    amount = Decimal(raw)
    if amount == amount.to_integral_value():
        return str(int(amount))
    return format(amount, "f")


def fingerprint(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}:{normalize(kind, value)}".encode()).hexdigest()
    return digest[:16]


def mask(kind: str, value: str) -> str:
    """Display-only. Never a round-trip of the original value."""
    text = str(value).strip()
    if kind == "email":
        local, _, domain = text.partition("@")
        shown = (local[:3] if local else "") + "***"
        return f"{shown}@{domain.lower()}"
    if kind == "iban":
        compact = text.replace(" ", "").upper()
        return compact[:4] + "***"
    if kind == "url":
        return text.split("?", 1)[0][:32] + "***"
    if kind == "amount":
        return "***"
    if len(text) <= 4:
        return "***"
    return text[:3] + "***"


def _as_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (int, float, Decimal)):
        return str(payload)
    return json.dumps(payload, default=str)


def extract_entities(
    payload: Any,
    kinds: Iterable[str] | None = None,
    *,
    include_amounts: bool = False,
) -> list[tuple[str, str]]:
    """Return ``(kind, original_value)`` pairs. Amounts require an opt-in."""
    requested = list(kinds) if kinds is not None else list(DEFAULT_KINDS)
    if include_amounts and "amount" not in requested:
        requested.append("amount")
    if not include_amounts:
        requested = [kind for kind in requested if kind != "amount"]

    text = _as_text(payload)
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind in requested:
        pattern = _PATTERNS.get(kind)
        if pattern is None:
            continue
        for match in pattern.finditer(text):
            raw = match.group()
            try:
                digest = fingerprint(kind, raw)
            except (InvalidOperation, ValueError):
                continue
            if digest in seen:
                continue
            seen.add(digest)
            found.append((kind, raw))
    return found


def resolve_path(obj: Any, path: str) -> list[Any]:
    """Resolve ``foo.bar`` and ``foo[].bar`` paths. No jsonpath dependency."""
    if obj is None:
        return []
    if not path:
        return [obj]

    current: list[Any] = [obj]
    for part in _path_parts(path):
        wildcard = part.endswith("[]")
        key = part[:-2] if wildcard else part
        nxt: list[Any] = []
        for node in current:
            if isinstance(node, dict):
                if key not in node:
                    continue
                val = node[key]
                if wildcard:
                    if isinstance(val, list):
                        nxt.extend(val)
                else:
                    nxt.append(val)
            elif isinstance(node, list) and wildcard and not key:
                nxt.extend(node)
        current = nxt
    return [value for value in current if value is not None]


def _path_parts(path: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    for char in path:
        if char == ".":
            if buf:
                parts.append("".join(buf))
                buf = []
            continue
        buf.append(char)
    if buf:
        parts.append("".join(buf))
    return parts
