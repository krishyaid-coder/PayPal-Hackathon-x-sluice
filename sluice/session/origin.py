"""Per-session origin index for typed entity fingerprints.

``sluice.session.provenance`` records taint marks and keeps the raw value
in RAM so later requests can be substring-matched. Origin is a different
index: it stores SHA-256 prefixes of ``kind:normalized``, a masked display
string, and the detector that fired on the source tool result. Nothing
sensitive is persisted. The map dies with the session, which is correct —
origin only means anything within one conversation.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from sluice.session.provenance import parse_json_safe

_BIND_KEYS = ("order_id", "cart_id")


@dataclass(frozen=True)
class OriginTag:
    session_id: str
    step: int
    source_server: str
    source_tool: str
    detector: str
    severity: str
    kind: str
    fingerprint: str
    masked: str


@dataclass
class PendingCall:
    tool: str
    verdict: str | None = None
    tag: OriginTag | None = None


class OriginIndex:
    def __init__(self) -> None:
        self._tags: dict[tuple[str, str], OriginTag] = {}
        self._verdicts: dict[tuple[str, str], str] = {}
        self._chains: dict[tuple[str, str], OriginTag] = {}
        self._process_tags: dict[str, OriginTag] = {}
        self._process_verdicts: dict[str, str] = {}
        self._process_chains: dict[str, OriginTag] = {}
        self._pending: dict[tuple[str, int | str], PendingCall] = {}
        self._last: dict[tuple[str, str], PendingCall] = {}
        self._steps: dict[str, int] = {}
        self._lock = threading.Lock()

    def next_step(self, session_id: str) -> int:
        with self._lock:
            self._steps[session_id] = self._steps.get(session_id, 0) + 1
            return self._steps[session_id]

    def record(self, tag: OriginTag) -> None:
        key = (tag.session_id, tag.fingerprint)
        with self._lock:
            # Keep the earliest origin. Later reads of the same entity do not
            # rewrite the chain the dashboard will show.
            self._tags.setdefault(key, tag)
            self._process_tags.setdefault(tag.fingerprint, tag)

    def lookup(self, session_id: str, fingerprint: str) -> OriginTag | None:
        with self._lock:
            return self._tags.get((session_id, fingerprint)) or self._process_tags.get(
                fingerprint
            )

    def bind_result(
        self,
        session_id: str,
        key: str,
        verdict: str,
        tag: OriginTag | None = None,
    ) -> None:
        bind_key = (session_id, str(key))
        with self._lock:
            self._verdicts[bind_key] = verdict
            self._process_verdicts[str(key)] = verdict
            if tag is not None:
                self._chains[bind_key] = tag
                self._process_chains[str(key)] = tag

    def verdict_for(self, session_id: str, key: str) -> str | None:
        with self._lock:
            return self._verdicts.get((session_id, str(key))) or self._process_verdicts.get(
                str(key)
            )

    def chain_for(self, session_id: str, key: str) -> OriginTag | None:
        with self._lock:
            return self._chains.get((session_id, str(key))) or self._process_chains.get(
                str(key)
            )

    def note_call(
        self,
        session_id: str,
        rpc_id: int | str | None,
        tool: str,
        verdict: str | None = None,
        tag: OriginTag | None = None,
    ) -> None:
        pending = PendingCall(tool=tool, verdict=verdict, tag=tag)
        with self._lock:
            self._last[(session_id, tool)] = pending
            if rpc_id is not None:
                self._pending[(session_id, rpc_id)] = pending

    def pending_for(
        self, session_id: str, rpc_id: int | str | None, tool: str | None
    ) -> PendingCall | None:
        with self._lock:
            if rpc_id is not None:
                found = self._pending.get((session_id, rpc_id))
                if found is not None:
                    return found
            if tool is not None:
                return self._last.get((session_id, tool))
        return None

    def clear(self, session_id: str | None = None) -> None:
        with self._lock:
            if session_id is None:
                self._tags.clear()
                self._verdicts.clear()
                self._chains.clear()
                self._process_tags.clear()
                self._process_verdicts.clear()
                self._process_chains.clear()
                self._pending.clear()
                self._last.clear()
                self._steps.clear()
                return
            self._tags = {k: v for k, v in self._tags.items() if k[0] != session_id}
            self._verdicts = {k: v for k, v in self._verdicts.items() if k[0] != session_id}
            self._chains = {k: v for k, v in self._chains.items() if k[0] != session_id}
            self._pending = {k: v for k, v in self._pending.items() if k[0] != session_id}
            self._last = {k: v for k, v in self._last.items() if k[0] != session_id}
            self._steps.pop(session_id, None)


def extract_bind_keys(payload: Any) -> list[str]:
    """Pull order/cart ids out of a gated tool's JSON-RPC result."""
    obj = payload
    if isinstance(payload, str):
        parsed = parse_json_safe(payload)
        obj = parsed if parsed is not None else {}
    if not isinstance(obj, dict):
        return []
    result = obj.get("result", obj)
    found: list[str] = []
    seen: set[str] = set()
    _collect_bind_keys(result, found, seen)
    return found


def _collect_bind_keys(obj: Any, found: list[str], seen: set[str]) -> None:
    if isinstance(obj, dict):
        for key in _BIND_KEYS:
            value = obj.get(key)
            if isinstance(value, str) and value and value not in seen:
                seen.add(value)
                found.append(value)
        ident = obj.get("id")
        if isinstance(ident, str) and ident and ident not in seen:
            seen.add(ident)
            found.append(ident)
        for item in obj.get("content") or []:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                inner = parse_json_safe(item["text"])
                if inner is not None:
                    _collect_bind_keys(inner, found, seen)
        for value in obj.values():
            if isinstance(value, (dict, list)):
                _collect_bind_keys(value, found, seen)
    elif isinstance(obj, list):
        for item in obj:
            _collect_bind_keys(item, found, seen)


_index: OriginIndex | None = None
_lock = threading.Lock()


def configure(_cfg: Any = None) -> OriginIndex:
    """Replace the process-wide index. Called from Pipeline.__init__."""
    global _index
    with _lock:
        _index = OriginIndex()
        return _index


def get_index() -> OriginIndex:
    global _index
    with _lock:
        if _index is None:
            _index = OriginIndex()
        return _index


def clear(session_id: str | None = None) -> None:
    get_index().clear(session_id)
