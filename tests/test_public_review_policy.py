from npmdiffwatch import abuse_workflow, reviewer
from npmdiffwatch.review_policy import JUDGMENT_POLICY, policy_block


def test_initial_and_evidence_contract_share_one_abuse_policy():
    for prompt in (reviewer.SYSTEM_PROMPT,abuse_workflow.SYSTEM):
        assert prompt.count(JUDGMENT_POLICY)==1
        assert policy_block() in prompt
    assert "The same binary from a raw IP or an unrelated domain is malicious" not in reviewer.SYSTEM_PROMPT


def test_short_stage_is_only_a_router_and_does_not_publish_a_threat_label():
    assert set(reviewer.SHORT_SCHEMA["properties"])=={"decision"}
    assert reviewer.SHORT_SCHEMA["properties"]["decision"]["enum"]==["clear","review"]
