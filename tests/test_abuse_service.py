from contextlib import nullcontext
import json

import pytest

from npmdiffwatch import abuse_service, abuse_workflow
from npmdiffwatch.evidence import AnalysisInput
from npmdiffwatch.review_budget import ReviewBudget, ReviewLimits
from npmdiffwatch.review_policy import POLICY_SHA256


def identity():
    return AnalysisInput("registry","fixture","1","a"*64,None,None,"release-change","b"*64,"1","1",
        POLICY_SHA256,"c"*64,"1","openai","test",True)


def test_public_initial_adapter_uses_actual_source_and_calls_no_private_engine():
    sources={"current":{"package.json":b'{}',"index.js":b"module.exports=1;"},"prior":{}}
    class Backend:
        primary_model="openai/test"
        last_usage=None
        def complete(self,**kwargs):
            if kwargs["schema"]==abuse_service.reviewer.SHORT_SCHEMA:
                return '{"decision":"review"}'
            brief=json.loads(kwargs["user_text"].splitlines()[2])
            ref=brief["source_blocks"][0]["ref"]
            return json.dumps({"classification":"benign","reasoning":"ordinary exported value",
                "concerning_observation":"","unresolved_abuse_question":"",
                "chain":{k:"" for k in ("source","sink","activation","baseline")},
                "citations":[{"ref":ref,"role":"explanation"}],
                "semantic":{"supports_selected_classification":True,"behavior":"ordinary","authorization":"ordinary",
                    "activation":"module","template_activation":"none","baseline_relation":"introduced",
                    "legitimate_functionality":"ordinary","unresolved_links":[],"vulnerability_observations":[]},
                "abuse_leads":[],"inspection_notes":["Not a security audit"]})
    admitted=[]
    result=abuse_service.review(identity(),sources,{},Backend(),
        ReviewBudget(ReviewLimits(128000,256000,8192,output_tokens_per_call=4096,max_model_calls=2)),
        lambda:admitted.append(1),nullcontext)
    assert result["status"]=="no_abuse_found" and result["route"]=="standard"
    assert [r["stage"] for r in result["initial_review_trace"]]==["short","full"]
    assert len(admitted)==2 and not result["claim_check"]["triggered"]


def test_public_adapter_does_not_mistake_context_admission_for_a_provider_failure():
    with pytest.raises(abuse_workflow.ContextOverflow):
        abuse_service.prepare(identity(),{"current":{"index.js":b"a"*100},"prior":{}},{},context_tokens=100)
    with pytest.raises(ValueError,match="another artifact"):
        abuse_service.prepare(identity(),{"current":{"index.js":b"x"},"prior":{}},
            {"current":{"artifact_sha256":"b"*64}})
