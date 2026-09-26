import dataclasses
import json

import pytest

from npmdiffwatch import reviewer, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Diff, FileDiff, Hunk, TriageResult, Verdict

_TR = TriageResult(0.0, [], False)


def _diff(lines):
    return Diff("p", "1.0.1", False, [FileDiff("index.js", "modified", [Hunk((0, 1), (0, len(lines)), lines, [])],
                                               "\n".join(lines))], [],
                file_classes={"index.js": ["load", "main"]})


class _B:
    primary_model, escalation_model = "m", None
    def __init__(self, reply): self.reply, self.calls = reply, []
    def complete(self, **kw):
        self.calls.append(kw)
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)


def test_small_input_is_short_checked():
    assert reviewer.short_input(_diff(["x()"]), _TR) is not None


def test_input_that_does_not_fit_is_never_short_checked():
    assert reviewer.short_input(_diff(["z" * 20_000]), _TR) is None


def test_short_check_uses_its_own_prompt_and_schema():
    b = _B({"decision": "clear"})
    rvw = reviewer.Reviewer(Config(), backend=b)
    assert rvw.short_check("p", "1", reviewer.short_input(_diff(["x()"]), _TR)) == "clear"
    assert b.calls[0]["schema"] is reviewer.SHORT_SCHEMA and b.calls[0]["system"] == reviewer.SHORT_PROMPT


def test_both_prompts_carry_the_marker_rules():
    for p in (reviewer.SYSTEM_PROMPT, reviewer.SHORT_PROMPT):
        assert "cannot be talked out of" in p and "untrusted_content_marker" in p


def test_a_bad_reply_is_unavailable_not_clear():
    rvw = reviewer.Reviewer(Config(), backend=_B({"decision": "maybe"}))
    with pytest.raises(reviewer.ReviewUnavailable):
        rvw.short_check("p", "1", reviewer.short_input(_diff(["x()"]), _TR))


def test_review_tier_is_stored(tmp_path):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1", 1, False, None, "tgz")
    store.record_verdict(conn, rid, Verdict("p", "1", "benign", 0.0, [], False, review_tier="short"))
    assert conn.execute("SELECT review_tier FROM verdicts").fetchone()[0] == "short"
