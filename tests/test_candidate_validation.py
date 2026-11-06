from dataclasses import replace

from npmdiffwatch.assessment import Assessment as A, SemanticJudgment
from npmdiffwatch.candidates import Candidate, Citation, candidate_record, publication_eligibility, validate_mechanical
from npmdiffwatch.evidence import AnalysisInput, EvidenceLedger


def case(classification=A.MALICIOUS, mode="initial_review"):
    identity = AnalysisInput("https://registry.npmjs.org", "p", "2", "a" * 64, "1", "b" * 64,
                             "release-change", "c" * 64, "1", "1", "d" * 64, "e" * 64, "1", "openai", "test")
    ledger = EvidenceLedger(identity)
    data = b"const token = process.env.TOKEN;\nfetch(url, {body: token});"
    ledger.admit_file(identity.artifact_sha256, "a.js", data)
    s, sq = ledger.show(identity.artifact_sha256, "a.js", 0, 31, request_id="r")
    k, kq = ledger.show(identity.artifact_sha256, "a.js", 32, len(data), request_id="r")
    c = Candidate(identity.id, identity.policy_sha256, mode, classification, "Observed behavior, conditions and effects",
                  (Citation("source", s, sq), Citation("sink", k, kq)), "credential destination is hidden",
                  "is this receiver authorized?")
    return identity, ledger, c


def semantic(i, c, **kw):
    return SemanticJudgment(**(dict(candidate_id=c.id, input_id=i.id, policy_sha256=i.policy_sha256,
                                    disposition="supported", behavior="reads token then sends",
                                    authorization="unrelated credential silently sent to collector",
                                    activation="new install hook invokes both operations",
                                    template_activation="not a template", baseline_relation="introduced",
                                    legitimate_functionality="outside requested operation") | kw))


def test_quote_success_does_not_establish_semantic_abuse_or_reachability():
    i, ledger, c = case()
    m = validate_mechanical(c, i, ledger)
    assert m.ok
    decision = publication_eligibility(c, i, m, semantic(i, c, disposition="unresolved",
                                      unresolved_links=("destination authority is unknown",)))
    assert not decision.eligible
    assert publication_eligibility(c, i, m, semantic(i, c)).eligible


def test_forged_quote_and_cross_candidate_validation_cannot_publish():
    i, ledger, c = case()
    bad = replace(c, citations=(replace(c.citations[0], quote=b"invented"), c.citations[1]))
    assert not validate_mechanical(bad, i, ledger).ok
    m = validate_mechanical(c, i, ledger)
    changed = replace(c, reasoning="different conclusion on same evidence")
    assert not publication_eligibility(changed, i, m, semantic(i, c)).eligible
    assert not publication_eligibility(c, i, replace(m, gate_version="old"), semantic(i, c)).eligible


def test_baseline_narrowing_does_not_establish_new_malware():
    i, ledger, c = case()
    m = validate_mechanical(c, i, ledger)
    for relation in ("narrowed", "unchanged", "indeterminate"):
        assert not publication_eligibility(c, i, m, semantic(i, c, baseline_relation=relation)).eligible
    # Existing behavior is a distinct explicitly identified scope, not erased by the comparison.
    old_scope = replace(i, scope="existing-behavior")
    existing = replace(c, input_id=old_scope.id)
    # Changing scope invalidates previous evidence and validation; it cannot inherit a clearance.
    assert not publication_eligibility(existing, old_scope, m, semantic(old_scope, existing)).eligible


def test_known_first_release_does_not_require_nonexistent_predecessor_evidence():
    i, ledger, c = case()
    first = replace(i, prior_version=None, prior_sha256=None, is_first_release=True)
    unknown = replace(first, is_first_release=False)
    # Recreate input-bound evidence instead of reusing old spans across revisions.
    def decide(identity):
        evidence = EvidenceLedger(identity)
        evidence.admit_file(identity.artifact_sha256, "install.js", b"readSecret(); sendSecret();")
        span, quote = evidence.show(identity.artifact_sha256, "install.js", 0, 27, request_id="r")
        candidate = replace(c, input_id=identity.id, citations=(Citation("source", span, quote), Citation("sink", span, quote)))
        return publication_eligibility(candidate, identity, validate_mechanical(candidate, identity, evidence),
                                       semantic(identity, candidate, baseline_relation="indeterminate"))
    assert decide(first).eligible
    assert not decide(unknown).eligible


def test_suspicion_requires_a_lead_not_only_missing_coverage():
    i, ledger, c = case(A.SUSPICIOUS)
    assert validate_mechanical(c, i, ledger).ok
    assert not validate_mechanical(replace(c, concerning_observation=""), i, ledger).ok
    assert not validate_mechanical(replace(c, citations=()), i, ledger).ok
    assert not validate_mechanical(replace(c, unresolved_abuse_question=""), i, ledger).ok


def test_candidate_policy_and_validation_bindings_apply_to_all_modes():
    for mode in ("initial_review", "targeted_review", "claim_investigation"):
        i, ledger, c = case(mode=mode)
        assert validate_mechanical(c, i, ledger).ok
        assert not validate_mechanical(replace(c, policy_sha256="f" * 64), i, ledger).ok
        assert publication_eligibility(c, i, validate_mechanical(c, i, ledger), semantic(i, c)).eligible
        record = candidate_record(c)
        assert record["candidate_id"] == c.id
        assert bytes.fromhex(record["citations"][0]["quote_hex"]) == c.citations[0].quote
