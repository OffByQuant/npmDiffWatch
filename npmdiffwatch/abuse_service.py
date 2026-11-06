"""Initial-review adapter for callers that already acquired sandboxed source.

Acquisition, durable scheduling, persistence and optional targeted/confirmation
callbacks belong to the application. This adapter never imports a local plugin,
opens package paths, executes source, sends alerts or overwrites prior verdicts.
"""
from . import abuse_workflow as contract, reviewer
from .review_tokens import request_tokens


def prepare(identity, sources, contexts, *, context_tokens=128000):
    packet = contract.Packet(identity, sources)
    for version, context in contexts.items():
        if context:
            expected = identity.artifact_sha256 if version == "current" else identity.prior_sha256
            if context.get("artifact_sha256") != expected:
                raise ValueError("execution context belongs to another artifact")
    paths = {"package.json"}
    paths.update(p for p in set(sources["current"]) | set(sources["prior"])
                 if sources["current"].get(p) != sources["prior"].get(p))
    frontier = list(paths)
    while frontier:
        path = frontier.pop()
        for context in contexts.values():
            metadata = context.get("files", {}).get(path, {})
            for key in ("imports", "readers", "reads"):
                for dependency in metadata.get(key, []):
                    if dependency not in paths:
                        paths.add(dependency)
                        frontier.append(dependency)
    for context in contexts.values():
        paths.update(p for p,m in context.get("files", {}).items() if m.get("class") in ("install", "load", "command"))
    metadata = {"scoped_file_count": sum(p in files for p in paths for files in sources.values()),
                "scope": "npm release change and activation; abuse detection, not security certification"}
    added = 0
    for path in sorted(paths, key=lambda p: (p != "package.json", p)):
        for version, files in sources.items():
            data = files.get(path)
            info = contexts.get(version, {}).get("files", {}).get(path, {})
            if not data or info.get("verified_inert"):
                continue
            cursor = 0
            while cursor < len(data):
                end = min(len(data), cursor + 4096)
                while end < len(data) and data[end] & 0xc0 == 0x80:
                    end -= 1
                packet.add(version, path, cursor, end)
                added += end - cursor
                cursor = end
                if added >= 32768:
                    count = request_tokens(contract.SYSTEM, contract.message(packet.brief(**metadata)), packet.schema())
                    if contract.route_context(count, context_tokens) == "targeted":
                        raise contract.ContextOverflow(count, context_tokens)
                    added = 0
    count = request_tokens(contract.SYSTEM, contract.message(packet.brief(**metadata)), packet.schema())
    if contract.route_context(count, context_tokens) == "targeted":
        raise contract.ContextOverflow(count, context_tokens)
    return packet, metadata


def review(identity, sources, contexts, backend, budget, admission, slot, *, targeted=None, claim_check=None,
           context_tokens=128000, short_check=True, trace=None):
    """Run the shared contract without assuming that source exhaustion is a goal.

    Optional callbacks are zero-argument targeted review and one-argument claim
    confirmation, supplied by the trusted application. They must consume the
    same host-owned admission/slot/budget and retain their own stage trace.
    """
    trace = [] if trace is None else trace

    def standard():
        packet, metadata = prepare(identity, sources, contexts, context_tokens=context_tokens)
        if short_check:
            decision = contract.invoke(backend, packet, budget, admission, slot, trace,
                system=reviewer.SHORT_PROMPT, schema=reviewer.SHORT_SCHEMA, stage="short", **metadata)
            if not isinstance(decision, dict) or decision.get("decision") not in ("clear", "review"):
                raise ValueError("invalid short routing response")
            metadata["short_routing_decision"] = decision["decision"]
        return contract.adjudicate(backend, packet, budget, admission, slot, trace, **metadata)

    result = contract.review_workflow(standard=standard, targeted=targeted, claim_check=claim_check)
    result["initial_review_trace"] = trace
    return result
