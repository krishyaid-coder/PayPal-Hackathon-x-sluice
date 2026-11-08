from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import structlog

from sluice.audit.preview import safe_preview
from sluice.detectors import supply_chain
from sluice.detectors.base import Hit, ScanContext
from sluice.detectors.entities import extract_entities, fingerprint, mask, resolve_path
from sluice.policy.engine import bootstrap_detectors, evaluate, resolve_action
from sluice.proxy.models import AuditEvent, PolicyViolation
from sluice.session import origin, taint
from sluice.session import pseudonym as pseudonym_session
from sluice.session.origin import OriginTag

if TYPE_CHECKING:
    from sluice.audit.sink import AuditSink
    from sluice.config.schema import SluiceConfig

log = structlog.get_logger()

# PII hits mean "this is an email", not "this content is untrusted".
# Origin tags only when a poison/injection/secret detector fired on the result.
_ORIGIN_TAG_CATEGORIES = frozenset({"prompt_injection", "tool_poisoning", "secrets"})


class Pipeline:
    def __init__(self, cfg: SluiceConfig, audit: AuditSink | None = None) -> None:
        self._cfg = cfg
        self._audit = audit
        bootstrap_detectors()
        taint.configure(cfg)
        origin.configure(cfg)
        pseudonym_session.configure(cfg)
        supply_chain.configure(cfg)

    def _reverse_pseudonyms(
        self, raw: str, session_id: str
    ) -> tuple[str, int, PolicyViolation | None]:
        """Substitute known pseudonyms with real values in outbound request bodies.

        Returns (body, substituted_count, block_violation). If the pipeline is
        configured fail-closed and the message contains a pseudonym-shaped
        token that is not in the session registry, returns a block violation
        with the raw body unchanged.
        """
        store = pseudonym_session.store()
        if store is None or not store.enabled:
            return raw, 0, None
        tokens = pseudonym_session.find_pseudonym_tokens(raw)
        if not tokens:
            return raw, 0, None

        registry = pseudonym_session.registry_for(session_id)
        assert registry is not None  # store.enabled is True

        unknown: list[str] = []
        substitutions: list[tuple[str, str]] = []
        for token in tokens:
            real = registry.lookup(token)
            if real is None:
                unknown.append(token)
            else:
                substitutions.append((token, real))

        if unknown and store.fail_closed_on_reverse:
            preview = ", ".join(unknown[:3]) + ("…" if len(unknown) > 3 else "")
            log.warning(
                "pseudonym_reverse_unknown",
                session_id=session_id,
                unknown=unknown[:5],
            )
            return raw, 0, PolicyViolation(
                rule="pseudonym_unknown",
                detail=(
                    f"Refusing call: outbound message contains unknown pseudonym "
                    f"tokens ({preview}). Session registry has no mapping. "
                    f"This is fail-closed behaviour."
                ),
                action="block",
                detectors=["pseudonym_unknown"],
            )

        body = raw
        for token, real in substitutions:
            body = body.replace(token, real)
        return body, len(substitutions), None

    def _tool_from_raw(self, raw: str) -> str | None:
        try:
            payload = json.loads(raw)
            if payload.get("method") == "tools/call":
                return payload.get("params", {}).get("name")
        except (json.JSONDecodeError, AttributeError):
            pass
        return None

    def _args_from_raw(self, raw: str) -> dict:
        try:
            payload = json.loads(raw)
            args = payload.get("params", {}).get("arguments")
            return args if isinstance(args, dict) else {}
        except (json.JSONDecodeError, AttributeError, TypeError):
            return {}

    def _origin_violation(
        self,
        *,
        reason: str,
        tag: OriginTag | None,
        argument_path: str,
        action: str,
    ) -> PolicyViolation:
        if tag is not None and reason == "inherited":
            detail = (
                f"Blocked: inherited origin verdict from {tag.source_tool} "
                f"({tag.kind} {tag.masked})."
            )
        elif tag is not None:
            detail = (
                f"Blocked: {tag.kind} {tag.masked} originated in "
                f"{tag.source_tool} ({tag.detector}) at step {tag.step}."
            )
        else:
            detail = "Blocked: inherited origin verdict from a prior gated call."
        if action == "flag":
            detail = detail.replace("Blocked:", "Flagged:", 1)
        return PolicyViolation(
            rule="origin_gate",
            detail=detail,
            action=action,
            detectors=["origin_gate"],
            blocked_by="origin_gate",
            origin_step=tag.step if tag else None,
            origin_tool=tag.source_tool if tag else None,
            origin_detector=tag.detector if tag else None,
            entity_kind=tag.kind if tag else None,
            entity_masked=tag.masked if tag else None,
            argument_path=argument_path,
        )

    def _origin_gate(
        self,
        raw: str,
        *,
        session_id: str,
        tool: str | None,
        rpc_id: int | str | None,
    ) -> PolicyViolation | None:
        cfg = self._cfg.origin
        if not cfg.enabled or not tool:
            return None
        band = cfg.band_of(tool)
        if band is None or band == "read_only":
            return None

        index = origin.get_index()
        args = self._args_from_raw(raw)
        hit_tag: OriginTag | None = None
        hit_path = ""
        reason = ""

        for spec in cfg.gated_arguments.get(tool, []):
            values = resolve_path(args, spec.path)
            kinds = list(spec.kinds)
            if "inherit" in kinds:
                for value in values:
                    key = str(value)
                    if index.verdict_for(session_id, key) == "block":
                        hit_tag = index.chain_for(session_id, key)
                        hit_path = spec.path
                        reason = "inherited"
                        break
                if reason == "inherited":
                    break
                continue
            if not cfg.track_amounts:
                kinds = [kind for kind in kinds if kind != "amount"]
            if not kinds:
                continue
            for value in values:
                extracted = extract_entities(
                    value, kinds=kinds, include_amounts=cfg.track_amounts
                )
                for kind, found in extracted:
                    tag = index.lookup(session_id, fingerprint(kind, found))
                    if tag:
                        hit_tag = tag
                        hit_path = spec.path
                        reason = "origin"
                        break
                if reason == "origin":
                    break
            if reason == "origin":
                break

        if not reason:
            index.note_call(session_id, rpc_id, tool, verdict="allow")
            return None

        action = cfg.actions.on_origin_hit.get(band, "block")
        stored = "block" if action == "block" else ("flag" if action == "flag" else "allow")
        index.note_call(session_id, rpc_id, tool, verdict=stored, tag=hit_tag)
        if action == "allow":
            return None
        return self._origin_violation(
            reason=reason,
            tag=hit_tag,
            argument_path=hit_path,
            action=action,
        )

    def _record_origin_from_hits(
        self,
        *,
        raw: str,
        session_id: str,
        step: int,
        upstream: str,
        tool: str | None,
        hits: list[Hit],
    ) -> None:
        if not self._cfg.origin.enabled or not hits:
            return
        tagging = [
            hit
            for hit in hits
            if hit.detector_id.split(".", 1)[0] in _ORIGIN_TAG_CATEGORIES
        ]
        if not tagging:
            return
        finding = tagging[0]
        extracted = extract_entities(
            raw, include_amounts=self._cfg.origin.track_amounts
        )
        index = origin.get_index()
        for kind, value in extracted:
            index.record(
                OriginTag(
                    session_id=session_id,
                    step=step,
                    source_server=upstream,
                    source_tool=tool or "",
                    detector=finding.detector_id,
                    severity=finding.severity,
                    kind=kind,
                    fingerprint=fingerprint(kind, value),
                    masked=mask(kind, value),
                )
            )

    def _bind_gated_result(
        self,
        *,
        raw: str,
        session_id: str,
        rpc_id: int | str | None,
        tool: str | None,
    ) -> None:
        pending = origin.get_index().pending_for(session_id, rpc_id, tool)
        if pending is None or not pending.verdict:
            return
        for key in origin.extract_bind_keys(raw):
            origin.get_index().bind_result(
                session_id, key, pending.verdict, tag=pending.tag
            )

    def _method_from_raw(self, raw: str) -> str | None:
        try:
            return json.loads(raw).get("method")
        except (json.JSONDecodeError, AttributeError):
            return None

    def _preview(
        self,
        raw: str,
        violation: PolicyViolation | None,
        hits: list[Hit] | None = None,
        extra_values: list[tuple[str, str]] | None = None,
        session_id: str | None = None,
    ) -> str:
        extras = list(extra_values or [])
        if session_id:
            for mark in taint.list_marks(session_id):
                if mark.value and mark.value in raw:
                    extras.append(("taint", mark.value))
        prop_hashes: list[str] = []
        if violation and violation.propagation:
            for edge in violation.propagation:
                digest = edge.get("value_hash") or ""
                if digest:
                    prop_hashes.append(digest)
        return safe_preview(
            method=self._method_from_raw(raw),
            tool=self._tool_from_raw(raw),
            hits=hits,
            violation=violation,
            extra_values=extras,
            propagation_hashes=prop_hashes,
        )

    async def _audit_write(
        self,
        *,
        session_id: str,
        upstream: str,
        direction: str,
        raw: str,
        violation: PolicyViolation | None,
        latency_us: int,
        client_ip: str | None = None,
        hits: list[Hit] | None = None,
        extra_values: list[tuple[str, str]] | None = None,
        tool: str | None = None,
        session_step: int | None = None,
    ) -> None:
        if not self._audit:
            return
        action = violation.action if violation else "pass"
        await self._audit.write(
            AuditEvent(
                session_id=session_id,
                upstream=upstream,
                direction=direction,
                method=self._method_from_raw(raw),
                tool=tool or self._tool_from_raw(raw),
                action=action,
                detectors=violation.detectors if violation else [],
                rule=violation.rule if violation else None,
                redacted_preview=self._preview(
                    raw,
                    violation,
                    hits=hits,
                    extra_values=extra_values,
                    session_id=session_id,
                ),
                latency_us=latency_us,
                preset_source=violation.preset_source if violation else None,
                client_ip=client_ip,
                propagation=violation.propagation if violation else None,
                session_step=session_step,
                blocked_by=violation.blocked_by if violation else None,
                origin_step=violation.origin_step if violation else None,
                origin_tool=violation.origin_tool if violation else None,
                origin_detector=violation.origin_detector if violation else None,
                entity_kind=violation.entity_kind if violation else None,
                entity_masked=violation.entity_masked if violation else None,
                argument_path=violation.argument_path if violation else None,
            )
        )

    async def inspect_request(
        self,
        raw: str,
        *,
        session_id: str,
        upstream: str,
        client_ip: str | None = None,
    ) -> tuple[str, PolicyViolation | None]:
        start = time.perf_counter_ns()
        step = origin.get_index().next_step(session_id)
        method = self._method_from_raw(raw)
        tool = self._tool_from_raw(raw)
        rpc_id = self.request_id_from_raw(raw)
        context = ScanContext("request", method, tool, upstream, session_id)

        # Reverse-pseudonym pass first. AI-authored outbound may contain
        # pseudonyms like EMAIL_A that need to become the real value before
        # the tool server sees them. Fail-closed on unknown pseudonyms.
        body_reversed, reversed_count, reverse_block = self._reverse_pseudonyms(
            raw, session_id
        )
        if reverse_block is not None:
            latency = (time.perf_counter_ns() - start) // 1000
            await self._audit_write(
                session_id=session_id,
                upstream=upstream,
                direction="request",
                raw=raw,
                violation=reverse_block,
                latency_us=latency,
                client_ip=client_ip,
                tool=tool,
                session_step=step,
            )
            log.warning(
                "pseudonym_reverse_blocked", upstream=upstream, session_id=session_id
            )
            return raw, reverse_block

        origin_violation = self._origin_gate(
            body_reversed, session_id=session_id, tool=tool, rpc_id=rpc_id
        )
        if origin_violation is not None:
            latency = (time.perf_counter_ns() - start) // 1000
            await self._audit_write(
                session_id=session_id,
                upstream=upstream,
                direction="request",
                raw=body_reversed,
                violation=origin_violation,
                latency_us=latency,
                client_ip=client_ip,
                tool=tool,
                session_step=step,
            )
            log.warning(
                "origin_gate_" + origin_violation.action,
                upstream=upstream,
                session_id=session_id,
                tool=tool,
                path=origin_violation.argument_path,
            )
            if origin_violation.action == "block":
                return body_reversed, origin_violation

        # If substitutions happened, skip the taint check. The user explicitly
        # opted into pseudonymized round-trip; blocking the reversed real value
        # with taint would defeat the whole feature.
        skip_taint = reversed_count > 0
        leak = None if skip_taint else taint.check(session_id, body_reversed)
        if leak:
            edge = taint.propagation_edge_for_leak(
                session_id,
                leak,
                sink_tool=tool,
                sink_upstream=upstream,
            )
            propagation = None
            if edge:
                propagation = [
                    {
                        "value_hash": edge.value_hash[:16],
                        "source_path": edge.source_path,
                        "source_tool": edge.source_tool,
                        "sink_tool": edge.sink_tool,
                        "sink_upstream": edge.sink_upstream,
                        "rule": edge.rule,
                    }
                ]
            # Wire taint through the policy engine so user rules apply. Fallback
            # order: no explicit rule (or default_action fallback) -> block, since
            # taint should never silently inherit a permissive default_action.
            # 'redact' is nonsensical for taint (the whole value triggers) so coerce
            # to block with a log; 'pass' also coerces to flag so the leak stays in
            # the audit trail.
            synthetic_hit = Hit(
                detector_id="taint_leak",
                start=0,
                end=0,
                matched="",
                label="cross-tool leak",
                severity="critical",
            )
            resolved = resolve_action([synthetic_hit], self._cfg, upstream, tool)
            if resolved is None or resolved.rule_detector == "default":
                action = "block"
            elif resolved.action == "redact":
                log.warning(
                    "taint_redact_coerced_to_block",
                    rule=resolved.rule_detector,
                )
                action = "block"
            elif resolved.action == "pass":
                log.warning(
                    "taint_pass_coerced_to_flag",
                    rule=resolved.rule_detector,
                )
                action = "flag"
            elif resolved.action == "flag":
                action = "flag"
            else:
                action = "block"

            violation = PolicyViolation(
                rule="taint_leak",
                detail="This value already appeared in an earlier tool response.",
                action=action,
                detectors=["taint_leak"],
                propagation=propagation,
            )
            latency = (time.perf_counter_ns() - start) // 1000
            await self._audit_write(
                session_id=session_id,
                upstream=upstream,
                direction="request",
                raw=raw,
                violation=violation,
                latency_us=latency,
                client_ip=client_ip,
                extra_values=[("taint_leak", leak)],
                tool=tool,
                session_step=step,
            )
            log.warning(f"taint_leak_{action}", upstream=upstream, session_id=session_id)
            return body_reversed, violation

        body, violation, hits = evaluate(body_reversed, context, self._cfg)
        if violation is None:
            violation = origin_violation
        latency = (time.perf_counter_ns() - start) // 1000
        await self._audit_write(
            session_id=session_id,
            upstream=upstream,
            direction="request",
            raw=body,
            violation=violation,
            latency_us=latency,
            client_ip=client_ip,
            hits=hits,
            tool=tool,
            session_step=step,
        )
        return body, violation

    async def inspect_response(
        self,
        raw: str,
        *,
        session_id: str,
        upstream: str,
        method: str | None = None,
        client_ip: str | None = None,
        tool: str | None = None,
    ) -> tuple[str, PolicyViolation | None]:
        start = time.perf_counter_ns()
        step = origin.get_index().next_step(session_id)
        rpc_id = self.request_id_from_raw(raw)
        if tool is None:
            pending = origin.get_index().pending_for(session_id, rpc_id, None)
            if pending is not None:
                tool = pending.tool
        if tool is None and method == "tools/call":
            tool = self._tool_from_raw(raw)
        context = ScanContext("response", method, tool, upstream, session_id)

        body, violation, hits = evaluate(raw, context, self._cfg)
        self._record_origin_from_hits(
            raw=raw,
            session_id=session_id,
            step=step,
            upstream=upstream,
            tool=tool,
            hits=hits,
        )
        if violation is None or violation.action in ("flag", "redact"):
            taint.mark_from_hits(
                session_id,
                [h.matched for h in hits],
                raw_json=body,
                source_tool=tool,
                source_upstream=upstream,
                source_method=method,
            )
        self._bind_gated_result(
            raw=raw, session_id=session_id, rpc_id=rpc_id, tool=tool
        )

        latency = (time.perf_counter_ns() - start) // 1000
        await self._audit_write(
            session_id=session_id,
            upstream=upstream,
            direction="response",
            raw=body,
            violation=violation,
            latency_us=latency,
            client_ip=client_ip,
            hits=hits,
            tool=tool,
            session_step=step,
        )
        return body, violation

    @staticmethod
    def block_response(request_id: int | str | None, message: str) -> str:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": message},
            }
        )

    @staticmethod
    def request_id_from_raw(raw: str) -> int | str | None:
        try:
            return json.loads(raw).get("id")
        except (json.JSONDecodeError, AttributeError):
            return None
