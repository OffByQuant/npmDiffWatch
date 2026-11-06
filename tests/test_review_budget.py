from dataclasses import replace

import pytest

from npmdiffwatch.review_budget import BudgetExceeded, ReviewBudget, ReviewLimits, conservative_text_tokens


def limits(**kw):
    return replace(ReviewLimits(8192, 32768, 12288), **kw)


def test_unknown_context_and_invalid_limits_fail_without_model_calls():
    with pytest.raises(ValueError):
        limits(context_tokens=None)
    with pytest.raises(ValueError):
        limits(timeout_s=float("nan"))
    with pytest.raises(ValueError):
        limits(context_tokens=2048)
    assert conservative_text_tokens("é") == 2


def test_small_context_requires_explicit_final_headroom():
    b = ReviewBudget(limits())
    with pytest.raises(ValueError, match="headroom"):
        b.reserve_request(1000, 2048, final=False)
    with pytest.raises(BudgetExceeded, match="context"):
        b.reserve_request(6000, 2048, final=True)
    assert b.model_calls == 0
    r = b.reserve_request(2000, 2048, final=False, final_input_tokens=2000, final_output_tokens=2048)
    assert b.model_calls == 1 and r.input_tokens == 3024
    b.finish_request(r, actual_output_tokens=100)
    assert b.output_tokens == 100
    with pytest.raises(ValueError):
        b.finish_request(r)


def test_retransmitted_context_and_failed_calls_remain_charged():
    b = ReviewBudget(limits(total_input_tokens=7000))
    b.reserve_request(2000, 2048, final=False, final_input_tokens=2000, final_output_tokens=2048)
    # The first call is abandoned: eviction/retry does not reset its input reservation.
    with pytest.raises(BudgetExceeded, match="cumulative input"):
        b.reserve_request(2000, 2048, final=False, final_input_tokens=2000, final_output_tokens=2048)
    assert b.model_calls == 1
    b.reserve_request(2000, 2048, final=True)
    assert b.input_tokens == 6048


def test_finalization_is_reserved_in_call_and_output_limits():
    b = ReviewBudget(limits(max_model_calls=1))
    with pytest.raises(BudgetExceeded, match="headroom"):
        b.reserve_request(1000, 1000, final=False, final_input_tokens=1000, final_output_tokens=1000)
    b.reserve_request(1000, 1000, final=True)
    with pytest.raises(BudgetExceeded):
        b.reserve_request(1000, 1000, final=True)


def test_tool_pagination_cannot_reset_scan_or_result_budget():
    b = ReviewBudget(limits(total_scan_bytes=100))
    b.reserve_tool(scan_bytes=60, response_bytes=100)
    with pytest.raises(BudgetExceeded, match="scan"):
        b.reserve_tool(scan_bytes=60, response_bytes=100)
    assert (b.tool_calls, b.scan_bytes, b.tool_bytes) == (1, 60, 100)
    with pytest.raises(BudgetExceeded, match="output"):
        b.reserve_tool(scan_bytes=0, response_bytes=4097)
    for _ in range(3):
        b.reserve_tool(scan_bytes=0, response_bytes=0)
    with pytest.raises(BudgetExceeded, match="call"):
        b.reserve_tool(scan_bytes=0, response_bytes=0)


def test_provider_overrun_is_charged_and_not_accepted_silently():
    b = ReviewBudget(limits())
    r = b.reserve_request(1000, 1000, final=True)
    with pytest.raises(BudgetExceeded, match="provider usage"):
        b.finish_request(r, actual_input_tokens=4000, actual_output_tokens=1001)
    assert b.input_tokens == 4000 and b.output_tokens == 1001


def test_deadline_is_whole_job_not_refreshed_per_turn():
    now = [0.0]
    b = ReviewBudget(limits(timeout_s=10), clock=lambda: now[0])
    now[0] = 8
    assert b.reserve_request(100, 100, final=True).timeout_s == 2
    now[0] = 11
    with pytest.raises(BudgetExceeded, match="deadline"):
        b.reserve_tool(scan_bytes=0, response_bytes=0)
