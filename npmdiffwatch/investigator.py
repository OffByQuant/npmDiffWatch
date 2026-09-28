"""The investigation loop: the model calls tools until it submits an answer, within step and time
limits. Every tool result is untrusted package content between random markers. The gate decides the outcome."""
import time

from . import investigate_gate as gate
from . import reviewer
from .backends import ReviewUnavailable, validate_verdict
from .investigate_tools import TOOL_SPECS, ToolError

SYSTEM = (reviewer._SECURITY + """

You are DiffWatch's investigator. A first review called this npm release malicious. Check this claim against
the package: use the tools to look at whatever you need (its files, its scripts, earlier versions, its
maintainer's other packages, its repository) and decide whether the claim holds. Nothing you do runs package
code; every tool only reads.

Decode with the decode tool; never decode in your head. To quote decoded code, give its ref (d1) as the path. Never try to contact a URL from the package.
Finish with submit_answer: your verdict and the reason for it. For malicious, chain_source and chain_sink are the
exact code (version "flagged") where it starts and where it does harm. For suspicious or benign, explanation is
the exact code (version "flagged") that shows why the claim is not what it seemed.""")


def _case(original: dict, marker: str) -> str:
    return (f"package: {original['package']}\nversion: {original['version']}\n"
            f"prior version: {original.get('prior_version') or 'none (first release)'}\n"
            f"untrusted_content_marker: {marker}\n\nThe first review (its words are about untrusted content):\n"
            f"{marker}\nreasoning: {original.get('reasoning')}\nchain source: {original.get('chain_source')}\n"
            f"chain sink: {original.get('chain_sink')}\ncited: {original.get('cited_hunk')}\n{marker}\n\n"
            f"Loaded versions: flagged" + (", prior" if original.get("prior_version") else "") + ".")


def _wrap(marker: str, text: str) -> str:
    return f"{marker}\n{text}\n{marker}"


def investigate(cfg, backend, ws, original: dict, *, clock=time.monotonic) -> dict:
    inv = cfg.investigator
    t0 = clock()
    marker = reviewer._new_marker()
    tools = TOOL_SPECS + [gate.SUBMIT_SPEC]
    messages = [backend.user_message(_case(original, marker))]
    steps, retries = 0, 0
    result = {"status": "failed", "verdict": None, "outcome": None, "confidence": None, "answer": {},
              "reason": "", "indicators": [], "gate_notes": [], "facts": ws.facts, "steps": 0, "tools": ws.log,
              "seconds": 0.0, "error": None}

    def done(**kw):
        result.update(kw, steps=steps, seconds=round(clock() - t0, 2))
        return result

    forced = False
    while True:
        if clock() - t0 > inv.timeout_s:
            return done(error="time limit reached")
        if steps >= inv.max_steps:
            if forced:
                return done(error="step limit reached without an answer")
            forced = True
            messages.append(backend.user_message("Step limit reached. Call submit_answer now with what you have."))
        steps += 1
        try:
            reply = backend.chat(model=backend.primary_model, system=SYSTEM, messages=messages, tools=tools,
                                 max_tokens=inv.max_output_tokens,
                                 timeout=max(1.0, inv.timeout_s - (clock() - t0)))
        except ReviewUnavailable as e:
            return done(error=str(e))
        messages.append(reply.assistant)
        if not reply.calls:
            messages.append(backend.user_message("Call a tool, or submit_answer when you have decided."))
            continue
        results = []
        for call in reply.calls:
            if call.name == "submit_answer" and call.error is None:
                try:
                    answer = validate_verdict(call.arguments, gate.ANSWER_SCHEMA)
                except ReviewUnavailable as e:
                    if retries >= 1:
                        return done(error=f"invalid answer: {e}")
                    retries += 1
                    results.append((call.id, f"error: invalid answer: {e}. Fix it and call submit_answer again."))
                    continue
                o = gate.judge(answer, ws)
                return done(status="ok", verdict=o.verdict, outcome=o.outcome,
                            confidence=answer.get("confidence"),
                            answer=answer, reason=answer.get("reason", ""),
                            indicators=answer.get("indicators") or [],
                            gate_notes=o.notes + [f"{o.rejected_quotes} quote(s) rejected"])
            if call.error is not None:
                results.append((call.id, f"error: {call.error}"))
                continue
            try:
                out = ws.call(call.name, call.arguments)
            except ToolError as e:
                out = f"error: {e}"
            results.append((call.id, _wrap(marker, out)))
        messages.extend(backend.tool_results(results))
