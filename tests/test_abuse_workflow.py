from copy import deepcopy

import pytest

from npmdiffwatch import abuse_dashboard, abuse_workflow as flow
from npmdiffwatch.evidence import AnalysisInput
from npmdiffwatch.review_policy import POLICY_SHA256


def packet():
    identity = AnalysisInput("registry", "fixture", "2", "a" * 64, "1", "b" * 64, "release-change",
        "c" * 64, "abuse-v1", "1", POLICY_SHA256, "d" * 64, "1", "openai", "test")
    sources = {"current": {"package.json": b'{"scripts":{"postinstall":"node index.js"}}',
        "index.js": b"fs.rmSync(path.join(os.homedir(), '.ssh'), {recursive:true});"},
        "prior": {"package.json": b'{"scripts":{"postinstall":"node index.js"}}', "index.js": b"module.exports=0;"}}
    result = flow.Packet(identity, sources)
    for version, files in sources.items():
        for path, data in files.items():
            result.add(version, path, 0, len(data))
    return result


def answer(p, classification="benign"):
    current = next(ref for ref,e in p.entries.items() if e["version"] == "current" and e["span"].path == "index.js")
    activation = next(ref for ref,e in p.entries.items() if e["version"] == "current" and e["span"].path == "package.json")
    prior = next(ref for ref,e in p.entries.items() if e["version"] == "prior" and e["span"].path == "index.js")
    return {"classification": classification, "reasoning": "fixture judgment", "concerning_observation": "observed effect",
        "unresolved_abuse_question": "is this authorized?" if classification == "suspicious" else "",
        "chain":{"source":current,"sink":current,"activation":activation,"baseline":prior} if classification == "malicious"
                else {key:"" for key in ("source","sink","activation","baseline")},
        "citations": [{"ref":current,"role":"source"}, {"ref":current,"role":"sink"},
                      {"ref":activation,"role":"activation"}, {"ref":prior,"role":"baseline"}],
        "semantic": {"supports_selected_classification": True, "behavior":"fixture", "authorization":"fixture",
            "activation":"fixture", "template_activation":"not template", "baseline_relation":"introduced",
            "legitimate_functionality":"fixture", "unresolved_links":[], "vulnerability_observations":[]},
        "abuse_leads": [] if classification == "benign" else [{"observation":"observed effect", "refs":[current],
            "status":"abusive" if classification == "malicious" else "needs_context", "question":"is this authorized?"}],
        "inspection_notes": []}


def test_no_abuse_is_not_blocked_by_general_security_audit_limitations():
    p = packet()
    wire = answer(p)
    wire["inspection_notes"] = ["Not every byte inspected", "External service and dependency internals unreviewed"]
    wire["semantic"]["vulnerability_observations"] = ["Potential command injection is not deliberate malware"]
    result = flow.validate(wire, p, set(p.entries))
    assert result["status"] == "no_abuse_found" and result["mechanical_validated"]
    assert "not a security certification" in result["scope"]


def test_host_owns_exact_quotations_and_all_original_source_addresses():
    p = packet()
    result = flow.validate(answer(p, "malicious"), p, set(p.entries))
    assert result["status"] == "malicious"
    for citation in result["candidate"]["citations"]:
        span = citation["span"]
        version = "current" if span["artifact_sha256"] == p.identity.artifact_sha256 else "prior"
        assert bytes.fromhex(citation["quote_hex"]) == p.sources[version][span["path"]][span["start"]:span["end"]]
    schema = p.schema()
    assert "code" not in schema["properties"]["citations"]["items"]["properties"]
    assert "enum" not in schema["properties"]["reasoning"]
    assert "enum" not in schema["properties"]["semantic"]["properties"]["behavior"]


def test_unknown_or_unissued_reference_cannot_be_recovered_by_matching_text():
    p = packet()
    wire = answer(p)
    wire["citations"][0]["ref"] = "e99"
    with pytest.raises(ValueError, match="not in this request"):
        flow.validate(wire, p, set(p.entries))
    wire = answer(p)
    with pytest.raises(ValueError, match="not in this request"):
        flow.validate(wire, p, {"e1"})


def test_malicious_endpoint_selection_is_explicit_not_inferred_from_a_sink_or_label():
    p=packet()
    wire=answer(p,"malicious")
    wire["chain"]["source"]=""
    with pytest.raises(ValueError,match="explicit source"):
        flow.validate(wire,p,set(p.entries))


def test_nonblocking_inspection_notes_do_not_erase_a_demonstrated_abusive_chain():
    p = packet()
    wire = answer(p, "malicious")
    wire["inspection_notes"] = ["Other package behavior was not inspected", "The observed endpoint owner's identity is unknown"]
    assert flow.validate(wire, p, set(p.entries))["status"] == "malicious"
    wire["semantic"]["unresolved_links"] = ["The causal link is unresolved, even if described as nonblocking"]
    with pytest.raises(ValueError, match="unresolved required links"):
        flow.validate(wire, p, set(p.entries))


def test_missing_context_or_failed_output_does_not_manufacture_suspicion():
    p = packet()
    wire = answer(p, "suspicious")
    wire["abuse_leads"] = []
    with pytest.raises(ValueError, match="concrete cited lead"):
        flow.validate(wire, p, set(p.entries))
    wire = answer(p)
    wire["abuse_leads"] = [{"observation":"actual concerning operation", "refs":["e2"], "status":"needs_context", "question":"where does the secret go?"}]
    with pytest.raises(ValueError, match="unresolved concrete abuse lead"):
        flow.validate(wire, p, set(p.entries))


@pytest.mark.parametrize("disposition", [False, "true", 1])
def test_selected_classification_support_is_literal_and_fail_closed(disposition):
    p = packet()
    wire = answer(p)
    wire["semantic"]["supports_selected_classification"] = disposition
    with pytest.raises(ValueError):
        flow.validate(wire, p, set(p.entries))


def test_context_overflow_promotes_only_the_typed_admission_failure():
    called = []
    def standard():
        raise flow.ContextOverflow(150000,128000)
    result = flow.review_workflow(standard=standard,
        targeted=lambda: {"status":"no_abuse_found"}, claim_check=lambda r: called.append(r))
    assert result["route"] == "targeted" and not called
    assert flow.route_context(150000) == "targeted"
    assert flow.route_context(2000) == "standard"
    def failed():
        raise ValueError("provider or citation failure")
    with pytest.raises(ValueError):
        flow.review_workflow(standard=failed, targeted=lambda: pytest.fail("must not promote"), claim_check=None)


@pytest.mark.parametrize("assessment", ["suspicious", "malicious"])
def test_claim_review_runs_only_for_surviving_threat_candidates_and_holds_disagreement(assessment):
    called = []
    def confirm(result):
        called.append(result["status"])
        return {"status":assessment,"mechanical_validated":True}
    result = flow.review_workflow(standard=lambda: {"status":assessment}, targeted=None, claim_check=confirm)
    assert called == [assessment] and result["status"] == assessment
    disputed = flow.review_workflow(standard=lambda: {"status":assessment}, targeted=None,
        claim_check=lambda r: {"status":"no_abuse_found","mechanical_validated":True})
    assert disputed["status"] == "held"
    absent = flow.review_workflow(standard=lambda: {"status":assessment}, targeted=None, claim_check=None)
    assert absent["status"] == "held"


def test_dashboard_separates_no_abuse_failures_history_and_human_authority():
    row = {"package":"<script>alert(1)</script>", "version":"1", "classification":"suspicious", "model":"test",
        "abuse_result":{"status":"no_abuse_found","inspection_notes":["<img src=x onerror=alert(1)>"]}}
    view = abuse_dashboard.render([row], completed=1)
    assert "No abuse found in assessed behavior" in view and "not a security certification" in view
    assert "<script>" not in view and "<img src=" not in view
    assert abuse_dashboard.state({**row,"human_label":"malicious"}) == "malicious"
    assert abuse_dashboard.state({**row,"abuse_result":{"status":"review_failed"}}) == "review_failed"
    assert abuse_dashboard.state({k:v for k,v in row.items() if k != "abuse_result"}) == "historical"


def test_policy_hold_displays_its_reason_without_rewriting_the_retained_candidate():
    row = {"package": "fixture", "version": "1", "model": "test", "abuse_result": {
        "status": "held", "candidate": {"reasoning": "retained original model claim"},
        "adjudication": {"reason": "Held: the cited observation does not establish the required abuse indicator."}}}
    rendered = abuse_dashboard.render([row])
    assert "Held: the cited observation" in rendered
    assert row["abuse_result"]["candidate"]["reasoning"] == "retained original model claim"
    assert "<script>" not in abuse_dashboard.render([{**row, "abuse_result": {"status": "held",
        "adjudication": {"reason": "<script>untrusted</script>"}}}])


def test_public_contract_has_no_private_investigation_imports():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(flow.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("internal")
    assert deepcopy(flow.WIRE_SCHEMA) == flow.WIRE_SCHEMA


def test_manual_npm_report_action_requires_validated_threat_or_human_authority():
    row={"package":"fixture","version":"1","classification":"suspicious","model":"test"}
    assert "Open npm report form" not in abuse_dashboard.render([row])
    result={"status":"malicious","mechanical_validated":True,"claim_check":{"triggered":True}}
    assert "Open npm report form" in abuse_dashboard.render([{**row,"abuse_result":result}])
    assert "Open npm report form" not in abuse_dashboard.render([{**row,"abuse_result":{**result,"status":"held"}}])
    assert "Open npm report form" in abuse_dashboard.render([{**row,"human_label":"malicious"}])


def test_public_renderer_has_no_experiment_specific_cohort_default():
    view = abuse_dashboard.render([], completed=7)
    assert "7 cases processed" in view
    assert "724" not in view and "remaining-cohort" not in view
    assert "7 / 10 cases processed" in abuse_dashboard.render([], completed=7, total=10)
