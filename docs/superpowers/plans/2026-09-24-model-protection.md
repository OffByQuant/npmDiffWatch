# Model Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop npmDiffWatch from overloading the user's model server. A circuit breaker with a health probe, an input-size cap derived from the endpoint's measured speed, a slowdown detector, and a host-memory guard for local endpoints, all wired into the existing LLM-review queue.

**Architecture:** A new `ReviewerGuard` (`npmdiffwatch/guard.py`) is rebuilt at the start of every batch from a `reviewer_stats` row. It measures input-reading speed from the token counts the server returns (`backend.last_usage`), caps review inputs to fit the timeout, and decides per review whether one may be sent now. The orchestrator asks it before every review (new releases and queue drains) and reports every outcome. Deferred reviews wait in the existing queue under a new reason `model_busy`. Host memory is read by `npmdiffwatch/hostmem.py`, standard library only.

**Tech Stack:** Python 3.11+, stdlib (`sqlite3`, `urllib`, `subprocess`, `ipaddress`), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-09-24-model-protection-design.md`

**Scope:** npmDiffWatch only. The PyDiffWatch port is a separate follow-up plan once this merges (spec §8).

## Global Constraints

- No new third-party dependencies (spec §5.5). Host memory uses `sysctl` (macOS) and `/proc` (Linux).
- Probe and calibration prompts never contain package content (spec §5.2, §5.3).
- `max_input_chars` stays the upper limit; the effective cap never exceeds it (spec §5.8).
- New queue reason is exactly `model_busy`; it spends no attempt and drains first (spec §5.6).
- Defaults, verbatim from the spec: `budget_safety = 0.6`, `probe_timeout = 60.0`, `slowdown_ratio = 0.3`, `degraded_pause_s = 900`, `host_memory_guard = "auto"`, `max_swap_used_pct = 75`. Cold-start cap 40,000 chars; minimum sample 2,000 prompt tokens; slowdown needs two consecutive slow reviews.
- Review decisions (spec §9): safety 0.6, checked on the live run; a degraded trip also posts `webhook_url`; one calibration request per new endpoint and model.
- Every behavior change is written test-first (repo CLAUDE.md, user's TDD rule). `ruff check npmdiffwatch/ tests/<touched>` clean on touched files.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Spec amendments made by this plan (Task 1 edits the spec to match)

1. Usage is exposed as `backend.last_usage` (set by every `complete()`/`ping()`), not by changing `complete()`'s return type. Every existing fake backend keeps working.
2. Breaker state (`state`, `detail`, `paused_until`, `slow_streak`) is stored in `reviewer_stats` too. A cron-driven `run` is a new process every tick, so in-memory state would reset the breaker every batch.
3. When a server reports no token usage, speed is estimated from `input_chars / 3.4` (the measured chars per token), so the budget still works instead of staying at the cold-start cap forever.

## Review Focus

1. **Server reports no `usage`** (some Ollama builds, custom proxies). Expected: speed is still measured from input size, and the cap adapts. Test in Task 3 (`test_rate_falls_back_to_chars_when_usage_missing`).
2. **llama-swap cold load inflates one sample** (the first review after the model was unloaded takes load time plus the review). Expected: one slow sample neither trips the slowdown nor drags the baseline down. Test in Task 4 (`test_single_slow_sample_does_not_trip_or_lower_baseline`).
3. **Queue rows built under an older, larger cap** (e.g. 557 rows queued at 200k while Qwen was down, drained later by a slower endpoint). Expected: auto-drain re-parks them as `too_large` with the endpoint's cap, instead of sending them or skipping them forever. Test in Task 6 (`test_auto_drain_reparks_rows_over_the_endpoint_cap_as_too_large`).
4. **Unsupported OS for the memory guard** (Windows, BSD). Expected: no crash, one notice, reviews admitted. Test in Task 5 (`test_unsupported_platform_is_inactive_not_an_error`).
5. **Wrong model id in config** (llama-swap returns 404 for the probe). Expected: breaker stays open and the warning carries the 404 hint text, so the user can see why. Test in Task 3 (`test_failed_probe_keeps_breaker_open_and_says_why`).

---

### Task 1: Backends report token usage; add `ping()` and `context_length()`

**Files:**
- Modify: `npmdiffwatch/backends.py` (add `_urllib_get_json`, `_usage_of`; `OpenAICompatibleBackend.__init__/complete/ping/context_length`; `AnthropicBackend.complete/ping/context_length`)
- Modify: `docs/superpowers/specs/2026-09-24-model-protection-design.md` (the three amendments above)
- Test: `tests/test_backend_usage.py`

**Interfaces:**
- Produces: `backend.last_usage: dict | None`, keys `prompt_tokens: int`, `completion_tokens: int`, optional `prompt_per_second: float`. `backend.ping(user_text: str, *, timeout: float) -> dict | None` (raises `ReviewUnavailable`). `backend.context_length() -> int | None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_backend_usage.py
"""Backends report the token counts the server returned, so the guard can measure endpoint speed."""
import pytest

from npmdiffwatch.backends import OpenAICompatibleBackend, ReviewUnavailable
from npmdiffwatch.reviewer import REVIEW_SCHEMA

_VERDICT = ('{"classification":"benign","confidence":0.9,"urgent":false,"recommended_action":"monitor",'
            '"attack_type":"none","cited_hunk":"","reasoning":"r"}')


def _post_returning(resp, seen=None):
    def post(url, payload, timeout, headers):
        if seen is not None:
            seen.append((url, payload, timeout))
        return resp
    return post


def test_complete_records_usage():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning(
        {"choices": [{"message": {"content": _VERDICT}}], "usage": {"prompt_tokens": 5000, "completion_tokens": 200}}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage == {"prompt_tokens": 5000, "completion_tokens": 200}


def test_complete_records_llamacpp_prompt_speed():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning(
        {"choices": [{"message": {"content": _VERDICT}}], "usage": {"prompt_tokens": 5000, "completion_tokens": 9},
         "timings": {"prompt_per_second": 1234.5}}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage["prompt_per_second"] == 1234.5


def test_missing_usage_is_none():
    b = OpenAICompatibleBackend("http://h:1/v1", "m", post=_post_returning({"choices": [{"message": {"content": _VERDICT}}]}))
    b.complete(model="m", system="s", user_text="u", schema=REVIEW_SCHEMA, max_tokens=10)
    assert b.last_usage is None


def test_ping_is_one_token_no_schema_and_returns_usage():
    seen = []
    b = OpenAICompatibleBackend("http://h:1/v1", "m", extra_body={"chat_template_kwargs": {"enable_thinking": False}},
                                post=_post_returning({"choices": [{"message": {"content": "OK"}}],
                                                      "usage": {"prompt_tokens": 7, "completion_tokens": 1}}, seen))
    assert b.ping("Reply with OK.", timeout=60.0) == {"prompt_tokens": 7, "completion_tokens": 1}
    url, payload, timeout = seen[0]
    assert url.endswith("/chat/completions") and timeout == 60.0
    assert payload["max_tokens"] == 1 and "response_format" not in payload
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}


def test_ping_failure_raises_review_unavailable():
    def post(*a):
        raise TimeoutError("timed out")
    with pytest.raises(ReviewUnavailable):
        OpenAICompatibleBackend("http://h:1/v1", "m", post=post).ping("x", timeout=1.0)


def test_context_length_from_models_listing():
    def get(url, timeout, headers):
        assert url == "http://h:1/v1/models"
        return {"data": [{"id": "other", "context_length": 1}, {"id": "m", "context_length": 262144}]}
    assert OpenAICompatibleBackend("http://h:1/v1", "m", get=get).context_length() == 262144


def test_context_length_from_llamacpp_props_then_none():
    def get(url, timeout, headers):
        if url.endswith("/v1/models"):
            return {"data": [{"id": "m"}]}
        assert url == "http://h:1/props"
        return {"default_generation_settings": {"n_ctx": 32768}}
    assert OpenAICompatibleBackend("http://h:1/v1", "m", get=get).context_length() == 32768

    def boom(url, timeout, headers):
        raise OSError("no")
    assert OpenAICompatibleBackend("http://h:1/v1", "m", get=boom).context_length() is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_backend_usage.py -q`
Expected: FAIL (`last_usage` / `ping` / `get` do not exist).

- [ ] **Step 3: Implement**

In `npmdiffwatch/backends.py`, after `_urllib_post_json` add:

```python
def _urllib_get_json(url: str, timeout: float, headers: dict | None = None) -> dict:
    egress.assert_web_scheme(url)
    req = urllib.request.Request(url, headers={"User-Agent": "npmdiffwatch/0.1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _usage_of(data) -> dict | None:
    """Token counts the server reported for a request, or None. llama.cpp also reports its measured
    prompt-reading speed (timings.prompt_per_second), which is more precise than tokens / wall time."""
    u = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(u, dict) or not isinstance(u.get("prompt_tokens"), int):
        return None
    out = {"prompt_tokens": u["prompt_tokens"], "completion_tokens": u.get("completion_tokens") or 0}
    pps = (data.get("timings") or {}).get("prompt_per_second")
    if isinstance(pps, (int, float)) and pps > 0:
        out["prompt_per_second"] = float(pps)
    return out
```

In `OpenAICompatibleBackend.__init__`, add a `get=None` keyword after `post=None`, and in the body:

```python
        self._get = get if get is not None else _urllib_get_json
        self.last_usage = None
```

In `OpenAICompatibleBackend.complete`, set `self.last_usage = None` as the first line of the body, and directly after the `data = self._post(...)` try/except add:

```python
        self.last_usage = _usage_of(data)
```

Add these methods to `OpenAICompatibleBackend`:

```python
    def ping(self, user_text, *, timeout) -> dict | None:
        """A minimal request (1 output token, no schema) for health probes and speed calibration.
        Raises ReviewUnavailable like complete(). Returns the reported usage, or None."""
        payload = {"model": self.primary_model, "messages": [{"role": "user", "content": user_text}],
                   "max_tokens": 1, "temperature": 0}
        if self.extra_body:
            payload.update(self.extra_body)
        try:
            data = self._post(f"{self.endpoint}/chat/completions", payload, timeout, self._auth_headers())
        except Exception as e:
            raise ReviewUnavailable(_egress_hint(e)) from e
        self.last_usage = _usage_of(data)
        return self.last_usage

    def context_length(self) -> int | None:
        """Best effort: the context window the server advertises for this model, else None."""
        try:
            for m in self._get(f"{self.endpoint}/models", 5.0, self._auth_headers()).get("data", []):
                if m.get("id") == self.primary_model:
                    for k in ("context_length", "max_model_len", "max_context_length"):
                        if isinstance(m.get(k), int) and m[k] > 0:
                            return m[k]
            root = self.endpoint[:-3] if self.endpoint.endswith("/v1") else self.endpoint
            props = self._get(f"{root}/props", 5.0, self._auth_headers())
            n_ctx = (props.get("default_generation_settings") or {}).get("n_ctx") or props.get("n_ctx")
            return n_ctx if isinstance(n_ctx, int) and n_ctx > 0 else None
        except Exception:
            return None
```

In `AnthropicBackend.__init__` add `self.last_usage = None`. In `AnthropicBackend.complete`, set `self.last_usage = None` first, and after the successful `resp = ...` add:

```python
        u = getattr(resp, "usage", None)
        self.last_usage = ({"prompt_tokens": u.input_tokens, "completion_tokens": u.output_tokens}
                           if u is not None and isinstance(getattr(u, "input_tokens", None), int) else None)
```

Add to `AnthropicBackend`:

```python
    def ping(self, user_text, *, timeout) -> dict | None:
        import anthropic
        try:
            resp = self.client.messages.create(model=self.primary_model, max_tokens=1, timeout=timeout,
                                               messages=[{"role": "user", "content": user_text}])
        except anthropic.APIError as e:
            raise ReviewUnavailable(str(e)) from e
        u = getattr(resp, "usage", None)
        self.last_usage = ({"prompt_tokens": u.input_tokens, "completion_tokens": u.output_tokens}
                           if u is not None and isinstance(getattr(u, "input_tokens", None), int) else None)
        return self.last_usage

    def context_length(self) -> int | None:
        return None
```

Edit the spec to match the amendments:
- In §5.3, replace the sentence starting `**Backend interface change:**` with: `**Backend interface:** every backend sets `last_usage` after each request: `{prompt_tokens, completion_tokens, prompt_per_second?}` or `None` if the server gave none. When `usage` is missing, speed is estimated from `input_chars / 3.4`. Backends also gain `ping(text, timeout)` and `context_length()`.`
- In §5.7, replace the paragraph starting `Keyed by` with: `Keyed by `base_url` and model, so switching models (Qwen → Gemma) or machines starts a fresh calibration. The table also stores the breaker state (`state`, `detail`, `paused_until` as wall-clock time, `slow_streak`). A cron-driven `run` is a new process every tick, so in-memory state would reset the breaker every batch.`

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest -q`
Expected: all pass (previous 150 + 7 new).

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/backends.py tests/test_backend_usage.py docs/superpowers/specs/2026-09-24-model-protection-design.md
git commit -m "feat(backends): report token usage; add ping() and context_length() for the reviewer guard"
```

---

### Task 2: `reviewer_stats` table

**Files:**
- Modify: `npmdiffwatch/store.py` (`SCHEMA`; add `get_reviewer_stats`, `save_reviewer_stats`)
- Test: `tests/test_reviewer_stats.py`

**Interfaces:**
- Produces: `store.get_reviewer_stats(conn, endpoint: str, model: str) -> dict | None` with keys `tok_s, chars_per_token, samples, state, detail, paused_until, slow_streak`. `store.save_reviewer_stats(conn, endpoint, model, *, tok_s, chars_per_token, samples, state, detail, paused_until, slow_streak) -> None` (upsert).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reviewer_stats.py
import dataclasses

from npmdiffwatch import store
from npmdiffwatch.config import Config


def test_stats_roundtrip_and_upsert(tmp_path):
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")
    conn = store.connect(cfg); store.init_schema(conn)
    assert store.get_reviewer_stats(conn, "http://h/v1", "m") is None
    kw = dict(tok_s=85.0, chars_per_token=3.4, samples=1, state="closed", detail="", paused_until=0.0, slow_streak=0)
    store.save_reviewer_stats(conn, "http://h/v1", "m", **kw)
    store.save_reviewer_stats(conn, "http://h/v1", "m", **{**kw, "samples": 2, "state": "open"})
    s = store.get_reviewer_stats(conn, "http://h/v1", "m")
    assert s["samples"] == 2 and s["state"] == "open" and s["tok_s"] == 85.0
    assert store.get_reviewer_stats(conn, "http://h/v1", "other-model") is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_reviewer_stats.py -q` — Expected: FAIL (`get_reviewer_stats` missing).

- [ ] **Step 3: Implement**

Append to the `SCHEMA` string in `npmdiffwatch/store.py`, before the closing `"""`:

```sql
CREATE TABLE IF NOT EXISTS reviewer_stats(endpoint TEXT, model TEXT, tok_s REAL, chars_per_token REAL,
  samples INTEGER, state TEXT, detail TEXT, paused_until REAL, slow_streak INTEGER, updated_at TEXT,
  PRIMARY KEY(endpoint, model));
```

Add after `pending_review_counts`:

```python
def get_reviewer_stats(conn, endpoint, model):
    row = conn.execute("SELECT tok_s, chars_per_token, samples, state, detail, paused_until, slow_streak "
                       "FROM reviewer_stats WHERE endpoint=? AND model=?", (endpoint, model)).fetchone()
    return dict(row) if row else None

def save_reviewer_stats(conn, endpoint, model, *, tok_s, chars_per_token, samples, state, detail,
                        paused_until, slow_streak):
    conn.execute("""INSERT INTO reviewer_stats(endpoint, model, tok_s, chars_per_token, samples, state, detail,
                        paused_until, slow_streak, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(endpoint, model) DO UPDATE SET tok_s=excluded.tok_s,
                        chars_per_token=excluded.chars_per_token, samples=excluded.samples,
                        state=excluded.state, detail=excluded.detail, paused_until=excluded.paused_until,
                        slow_streak=excluded.slow_streak, updated_at=excluded.updated_at""",
                 (endpoint, model, tok_s, chars_per_token, samples, state, detail, paused_until,
                  slow_streak, _now()))
    conn.commit()
```

- [ ] **Step 4: Run** `python -m pytest -q` — Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/store.py tests/test_reviewer_stats.py
git commit -m "feat(store): reviewer_stats table for measured endpoint speed and breaker state"
```

---

### Task 3: `ReviewerGuard`: speed budget, calibration, circuit breaker

**Files:**
- Create: `npmdiffwatch/guard.py`
- Modify: `npmdiffwatch/config.py` (`ReviewerConfig`: `budget_safety`, `probe_timeout`)
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: Task 1 `backend.ping`, `backend.context_length`; Task 2 `store.get_reviewer_stats`/`save_reviewer_stats`.
- Produces: `ReviewerGuard(cfg, backend, conn, *, clock=time.time, memory=None, out=None)` with `begin_batch()`, `admit() -> str | None`, `input_cap_chars() -> int`, `cap_explain() -> str`, `record_success(usage, secs, input_chars)`, `record_timeout()`, `status() -> dict` (`state, detail, tok_s, cap_chars, host_memory`). Module-level: `PROBE_TEXT`, `CALIBRATION_TEXT`, `describe(status: dict) -> str`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_guard.py
import dataclasses

from npmdiffwatch import guard as g, store
from npmdiffwatch.backends import ReviewUnavailable
from npmdiffwatch.config import Config


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class Backend:
    """ping() advances the clock by `secs_per_1k_chars` per 1,000 chars sent, like a real prefill."""
    def __init__(self, clock, secs_per_1k_chars=0.0, usage_tokens_per_char=1 / 3.4, fail=None, ctx=None):
        self.clock, self.k, self.tpc, self.fail, self.ctx, self.pings = clock, secs_per_1k_chars, usage_tokens_per_char, fail, ctx, []

    def ping(self, text, *, timeout):
        self.pings.append((len(text), timeout))
        if self.fail:
            raise ReviewUnavailable(self.fail)
        self.clock.t += self.k * len(text) / 1000
        return {"prompt_tokens": int(len(text) * self.tpc), "completion_tokens": 1} if self.tpc else None

    def context_length(self):
        return self.ctx


def _cfg(tmp_path, **rv):
    c = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite")
    return dataclasses.replace(c, reviewer=dataclasses.replace(c.reviewer, **rv))


def _guard(tmp_path, backend=None, clock=None, **rv):
    cfg = _cfg(tmp_path, **rv)
    conn = store.connect(cfg); store.init_schema(conn)
    clock = clock or Clock()
    said = []
    return g.ReviewerGuard(cfg, backend or Backend(clock), conn, clock=clock, memory=None, out=said.append), said


def test_cold_start_cap_until_measured(tmp_path):
    gd, _ = _guard(tmp_path)
    assert gd.input_cap_chars() == 40_000


def test_qwen_replay_cap_fits_the_timeout(tmp_path):
    # Last night: ~85 tok/s, 300 s timeout, 3.4 chars/token -> 85*300*0.6*3.4 ≈ 52k chars.
    gd, _ = _guard(tmp_path)
    gd.tok_s = 85.0
    assert 51_000 <= gd.input_cap_chars() <= 53_000
    assert "85 tok/s" in gd.cap_explain()


def test_fast_endpoint_is_limited_only_by_max_input_chars(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.tok_s = 5000.0
    assert gd.input_cap_chars() == 200_000


def test_context_window_caps_the_input(tmp_path):
    clock = Clock()
    gd, _ = _guard(tmp_path, Backend(clock, secs_per_1k_chars=0.001, ctx=32_768), clock)
    gd.begin_batch()
    assert gd.input_cap_chars() < 32_768 * 3.4


def test_anthropic_skips_the_budget(tmp_path):
    gd, _ = _guard(tmp_path, provider="anthropic")
    assert gd.input_cap_chars() == 200_000


def test_calibration_probes_first_then_measures_without_package_content(tmp_path):
    clock = Clock()
    be = Backend(clock, secs_per_1k_chars=1.0)        # ~3.4 chars/token -> ~294 tok/s
    gd, said = _guard(tmp_path, be, clock)
    gd.begin_batch()
    assert [n for n, _ in be.pings] == [len(g.PROBE_TEXT), len(g.CALIBRATION_TEXT)]
    assert 250 < gd.tok_s < 350
    assert any("tokens/s" in s for s in said)
    # stored: a new guard on the same DB starts measured, with no calibration request
    be2 = Backend(clock)
    gd2 = g.ReviewerGuard(gd.cfg, be2, gd.conn, clock=clock, memory=None, out=said.append)
    gd2.begin_batch()
    assert be2.pings == [] and gd2.tok_s == gd.tok_s


def test_failed_calibration_keeps_cold_start_cap_and_retries_next_batch(tmp_path):
    clock = Clock()
    be = Backend(clock, fail="timed out")
    gd, _ = _guard(tmp_path, be, clock)
    gd.begin_batch()
    assert gd.tok_s is None and gd.input_cap_chars() == 40_000
    be.fail, be.k = None, 1.0
    gd2 = g.ReviewerGuard(gd.cfg, be, gd.conn, clock=clock, memory=None, out=lambda m: None)
    gd2.begin_batch()
    assert gd2.tok_s is not None


def test_rate_falls_back_to_chars_when_usage_missing(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.record_success(None, secs=10.0, input_chars=34_000)   # ≈10k tokens / 10 s
    assert 950 < gd.tok_s < 1050


def test_small_requests_do_not_count_as_speed_samples(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.record_success({"prompt_tokens": 500, "completion_tokens": 200}, secs=30.0, input_chars=1_700)
    assert gd.tok_s is None


def test_timeout_opens_breaker_until_a_probe_succeeds(tmp_path):
    clock = Clock()
    be = Backend(clock)
    gd, said = _guard(tmp_path, be, clock)
    gd.tok_s = 100.0
    assert gd.admit() is None
    gd.record_timeout()
    assert gd.admit() == "breaker open after timeout"
    assert any("timed out" in s for s in said)
    # next batch: a fresh guard from the DB is still open, probes, and closes
    gd2 = g.ReviewerGuard(gd.cfg, be, gd.conn, clock=clock, memory=None, out=said.append)
    assert gd2.admit() == "breaker open after timeout"
    gd2.begin_batch()
    assert gd2.admit() is None and be.pings[-1][0] == len(g.PROBE_TEXT)


def test_failed_probe_keeps_breaker_open_and_says_why(tmp_path):
    clock = Clock()
    be = Backend(clock, fail="reviewer endpoint returned HTTP 404: check the model name")
    gd, said = _guard(tmp_path, be, clock)
    gd.tok_s = 100.0
    gd.record_timeout()
    gd.begin_batch()
    assert gd.admit() == "breaker open after timeout"
    assert any("HTTP 404" in s for s in said)


def test_status_and_describe(tmp_path):
    gd, _ = _guard(tmp_path)
    gd.tok_s = 85.0
    st = gd.status()
    assert st["state"] == "closed" and st["tok_s"] == 85.0 and st["host_memory"] is None
    assert "85 tok/s" in g.describe(st) and "input cap" in g.describe(st)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_guard.py -q` — Expected: FAIL (`No module named 'npmdiffwatch.guard'`).

- [ ] **Step 3: Implement**

Add to `ReviewerConfig` in `npmdiffwatch/config.py`, after `max_pending_per_tick`:

```python
    budget_safety: float = 0.6         # a review may be predicted to use at most this share of `timeout`
    probe_timeout: float = 60.0        # health probe / calibration (covers llama-swap loading a model)
```

Create `npmdiffwatch/guard.py`:

```python
"""ReviewerGuard: decides whether a review may be sent to the model endpoint now, and how large it may be.

Design: docs/superpowers/specs/2026-09-24-model-protection-design.md. A guard is rebuilt at the start of
every batch from its reviewer_stats row, so the measured speed and the breaker state survive restarts (a
cron-driven `run` is a new process every tick)."""
import logging
import time

from . import store
from .backends import ReviewUnavailable
from .reviewer import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

MIN_SAMPLE_TOKENS = 2000     # smaller prompts are dominated by fixed overhead, not reading speed
COLD_START_CAP = 40_000      # chars allowed per review until the endpoint's speed is measured
DEFAULT_CPT = 3.4            # chars per token, measured on review inputs (2026-09-24)
EWMA = 0.3
PROBE_TEXT = "Reply with OK."
CALIBRATION_TEXT = "The quick brown fox jumps over the lazy dog. " * 400   # ~4k tokens; never package content


def _rate(usage, secs, input_chars):
    """Input-reading speed (tokens/s) from one request, or None if overhead would dominate it."""
    if usage and usage.get("prompt_per_second"):
        return float(usage["prompt_per_second"])
    tokens = usage["prompt_tokens"] if usage else input_chars / DEFAULT_CPT
    if tokens < MIN_SAMPLE_TOKENS or secs <= 0:
        return None
    return tokens / secs


def describe(status):
    """One line for `pending` and the dashboard."""
    state = {"closed": "reviews on", "open": "reviews paused (timeout)",
             "degraded": "reviews paused (model degrading)"}.get(status["state"], status["state"])
    speed = f"{status['tok_s']:.0f} tok/s" if status.get("tok_s") else "speed not measured yet"
    line = f"{state} · {speed} · input cap {status['cap_chars']:,} chars"
    if status.get("host_memory"):
        line += f" · host memory: {status['host_memory']}"
    return line


class ReviewerGuard:
    def __init__(self, cfg, backend, conn, *, clock=time.time, memory=None, out=None):
        rc = cfg.reviewer
        self.cfg, self.rc, self.backend, self.conn, self.clock, self.memory = cfg, rc, backend, conn, clock, memory
        self.out = out or (lambda msg: print(msg, flush=True))
        self.endpoint = rc.base_url if rc.provider == "openai" else rc.provider
        self.model = rc.model
        self.measured = rc.provider == "openai"   # hosted APIs read input far faster than any timeout here
        s = store.get_reviewer_stats(conn, self.endpoint, self.model) or {}
        self.tok_s = s.get("tok_s")
        self.cpt = s.get("chars_per_token") or DEFAULT_CPT
        self.samples = s.get("samples") or 0
        self.state = s.get("state") or "closed"
        self.detail = s.get("detail") or ""
        self.paused_until = s.get("paused_until") or 0.0
        self.slow_streak = s.get("slow_streak") or 0
        self.ctx_tokens = None

    def begin_batch(self):
        """Once per batch, before any review. A paused endpoint gets a health probe; an unmeasured one gets
        a calibration request, sent after a probe so a model llama-swap is still loading isn't timed."""
        if self.state != "closed":
            if self.clock() < self.paused_until:
                return
            try:
                self.backend.ping(PROBE_TEXT, timeout=self.rc.probe_timeout)
            except ReviewUnavailable as e:
                self._say(f"reviewer endpoint {self.endpoint} is still not answering ({e}); reviews stay paused")
                return
            self._set("closed", "")
            self._say(f"reviewer endpoint {self.endpoint} answered the health probe; reviews resume")
        if not self.measured:
            return
        if self.ctx_tokens is None:
            self.ctx_tokens = self.backend.context_length()
        if self.tok_s is None:
            self._calibrate()

    def _calibrate(self):
        try:
            self.backend.ping(PROBE_TEXT, timeout=self.rc.probe_timeout)
            t = self.clock()
            usage = self.backend.ping(CALIBRATION_TEXT, timeout=self.rc.probe_timeout)
            secs = self.clock() - t
        except ReviewUnavailable as e:
            logger.warning("reviewer calibration failed for %s: %s", self.endpoint, e)
            return
        rate = _rate(usage, secs, len(CALIBRATION_TEXT))
        if rate:
            self.tok_s = rate
            self._save()
            self.out(f"[npmdiffwatch] reviewer endpoint {self.endpoint} reads ~{rate:.0f} tokens/s; "
                     f"review inputs capped at {self.input_cap_chars():,} chars")

    def admit(self):
        """None if a review may be sent now; otherwise why not (stored as the model_busy detail)."""
        if self.state != "closed":
            return self.detail
        if self.memory is not None:
            why = self.memory.pressure()
            if why:
                return f"host memory: {why}"
        return None

    def input_cap_chars(self):
        cap = self.rc.max_input_chars
        if not self.measured:
            return cap
        if self.tok_s is None:
            return min(cap, COLD_START_CAP)
        cap = min(cap, int(self.tok_s * self.rc.timeout * self.rc.budget_safety * self.cpt))
        if self.ctx_tokens:
            room = self.ctx_tokens - self.rc.max_output_tokens - len(SYSTEM_PROMPT) / DEFAULT_CPT
            cap = min(cap, int(room * self.cpt))
        return max(cap, 0)

    def cap_explain(self):
        cap = self.input_cap_chars()
        if self.measured and self.tok_s:
            return (f"this endpoint's cap is {cap:,} chars (≈{self.tok_s:.0f} tok/s × {self.rc.timeout:.0f}s "
                    f"× {self.rc.budget_safety})")
        return f"this endpoint's cap is {cap:,} chars"

    def record_success(self, usage, secs, input_chars):
        rate = _rate(usage, secs, input_chars)
        if rate is None:
            return
        self.tok_s = rate if self.tok_s is None else (1 - EWMA) * self.tok_s + EWMA * rate
        if usage and usage.get("prompt_tokens", 0) >= MIN_SAMPLE_TOKENS:
            self.cpt = (1 - EWMA) * self.cpt + EWMA * (input_chars / usage["prompt_tokens"])
        self.samples += 1
        self._save()

    def record_timeout(self):
        self._set("open", "breaker open after timeout")
        self._say(f"reviewer endpoint {self.endpoint} timed out; no more reviews this batch. The next batch "
                  f"probes it first (the server may still be working on the abandoned request)")

    def status(self):
        return {"state": self.state, "detail": self.detail,
                "tok_s": round(self.tok_s, 1) if self.tok_s else None,
                "cap_chars": self.input_cap_chars(),
                "host_memory": (self.memory.pressure() or "ok") if self.memory is not None else None}

    def _set(self, state, detail, paused_until=0.0):
        self.state, self.detail, self.paused_until = state, detail, paused_until
        if state == "closed":
            self.slow_streak = 0
        self._save()

    def _save(self):
        store.save_reviewer_stats(self.conn, self.endpoint, self.model, tok_s=self.tok_s, chars_per_token=self.cpt,
                                  samples=self.samples, state=self.state, detail=self.detail,
                                  paused_until=self.paused_until, slow_streak=self.slow_streak)

    def _say(self, msg):
        full = f"[npmdiffwatch] WARNING: {msg}"
        self.out(full)
        logger.warning(full)
```

- [ ] **Step 4: Run** `python -m pytest -q && ruff check npmdiffwatch/guard.py tests/test_guard.py` — Expected: all pass, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/guard.py npmdiffwatch/config.py tests/test_guard.py
git commit -m "feat(guard): size review inputs by measured endpoint speed; circuit breaker with health probe"
```

---

### Task 4: Slowdown detector (with webhook alert)

**Files:**
- Modify: `npmdiffwatch/guard.py` (`record_success`; import `notifier`)
- Modify: `npmdiffwatch/notifier.py` (extract `post_webhook`)
- Modify: `npmdiffwatch/config.py` (`slowdown_ratio`, `degraded_pause_s`)
- Test: `tests/test_guard.py` (append), `tests/test_notifier_webhook.py` (append)

**Interfaces:**
- Consumes: Task 3 guard internals (`_set`, `_say`, `slow_streak`, `paused_until`).
- Produces: state `"degraded"` with detail `"degraded"`; `begin_batch()` probes only once `clock() >= paused_until`. `notifier.post_webhook(cfg, text) -> bool` (False when no `webhook_url` or delivery failed; never raises).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_guard.py`)

```python
def _u(tokens):
    return {"prompt_tokens": tokens, "completion_tokens": 100}


def test_single_slow_sample_does_not_trip_or_lower_baseline(tmp_path):
    gd, said = _guard(tmp_path)
    gd.tok_s = 100.0
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)     # 20 tok/s: e.g. llama-swap cold load
    assert gd.admit() is None and gd.tok_s == 100.0
    gd.record_success(_u(10_000), secs=100.0, input_chars=34_000)     # back to normal resets the streak
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    assert gd.admit() is None


def test_two_consecutive_slow_reviews_pause_with_a_warning(tmp_path):
    clock = Clock()
    be = Backend(clock)
    gd, said = _guard(tmp_path, be, clock)
    gd.tok_s = 100.0
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    assert gd.admit() == "degraded" and gd.tok_s == 100.0
    assert any("20% of its measured speed" in s for s in said)
    gd.begin_batch()                                   # still inside the pause: no probe
    assert be.pings == []
    clock.t += 901
    gd.begin_batch()
    assert gd.admit() is None and len(be.pings) == 1
```

```python
def test_degraded_also_posts_the_webhook(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(g.notifier, "post_webhook", lambda cfg, text: sent.append(text) or True)
    gd, _ = _guard(tmp_path)
    gd.tok_s = 100.0
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    assert sent == []
    gd.record_success(_u(10_000), secs=500.0, input_chars=34_000)
    assert len(sent) == 1 and "measured speed" in sent[0]
```

Append to `tests/test_notifier_webhook.py`:

```python
def test_post_webhook_without_url_sends_nothing(monkeypatch):
    monkeypatch.setattr(notifier.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert notifier.post_webhook(Config(), "x") is False


def test_post_webhook_never_raises(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("down")
    monkeypatch.setattr(notifier.urllib.request, "urlopen", boom)
    assert notifier.post_webhook(Config(webhook_url="https://hooks.example.com/x"), "x") is False
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/test_guard.py tests/test_notifier_webhook.py -q` — Expected: the new tests FAIL (slow samples lower `tok_s`; no degraded state; no `post_webhook`).

- [ ] **Step 3: Implement**

In `npmdiffwatch/notifier.py`, add above `emit` and use it from `emit` (replace the `if cfg.webhook_url: try: ... except Exception: pass` block with `post_webhook(cfg, _render(verdict))`):

```python
def post_webhook(cfg, text) -> bool:
    """POST {"text": text} to cfg.webhook_url. False when none is set or delivery failed; never raises,
    because an alert must not break a scan."""
    if not cfg.webhook_url:
        return False
    try:
        egress.assert_web_scheme(cfg.webhook_url)
        body = json.dumps({"text": text}).encode()
        req = urllib.request.Request(cfg.webhook_url, data=body,
                                     headers={"Content-Type": "application/json", "User-Agent": "npmdiffwatch/0.1"})
        urllib.request.urlopen(req, timeout=cfg.fetch_timeout_s)
        return True
    except Exception:
        return False
```

In `npmdiffwatch/guard.py`, change `from . import store` to `from . import notifier, store`, and make `_say` return the message it printed (`return full` as its last line).

Add to `ReviewerConfig`, after `probe_timeout`:

```python
    slowdown_ratio: float = 0.3        # a review below this share of measured speed counts as slow
    degraded_pause_s: float = 900.0    # after two slow reviews in a row, pause this long before probing
```

In `ReviewerGuard.record_success`, insert between `if rate is None: return` and the `self.tok_s = ...` line:

```python
        if self.tok_s is not None and rate < self.rc.slowdown_ratio * self.tok_s:
            self.slow_streak += 1                     # slow samples never lower the baseline
            if self.slow_streak >= 2:
                pct = 100 * rate / self.tok_s
                self._set("degraded", "degraded", self.clock() + self.rc.degraded_pause_s)
                msg = self._say(f"reviewer endpoint {self.endpoint} is running at {pct:.0f}% of its measured speed — "
                                f"the model server is likely short on memory or swapping; consider restarting it. "
                                f"Reviews pause for {self.rc.degraded_pause_s:.0f}s")
                notifier.post_webhook(self.cfg, msg)
            else:
                self._save()
            return
        self.slow_streak = 0
```

- [ ] **Step 4: Run** `python -m pytest -q` — Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/guard.py npmdiffwatch/notifier.py npmdiffwatch/config.py tests/test_guard.py tests/test_notifier_webhook.py
git commit -m "feat(guard): pause reviews and alert the webhook when the endpoint runs far below its measured speed"
```

---

### Task 5: Host memory guard (local endpoints)

**Files:**
- Create: `npmdiffwatch/hostmem.py`
- Modify: `npmdiffwatch/guard.py` (`memory` default `"auto"`)
- Modify: `npmdiffwatch/config.py` (`host_memory_guard`, `max_swap_used_pct`)
- Test: `tests/test_hostmem.py`

**Interfaces:**
- Produces: `HostMemory(max_swap_used_pct, *, system=None, sysctl=_sysctl, read=_read).pressure() -> str | None`. `hostmem.is_loopback(base_url) -> bool`. `hostmem.for_config(cfg) -> HostMemory | None`.
- Changes: `ReviewerGuard(..., memory="auto")`. `"auto"` resolves through `hostmem.for_config(cfg)`. Existing tests pass `memory=None` explicitly.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_hostmem.py
import dataclasses

from npmdiffwatch import hostmem
from npmdiffwatch.config import Config


def _darwin(swap, level="1"):
    vals = {"vm.swapusage": swap, "kern.memorystatus_vm_pressure_level": level}
    return hostmem.HostMemory(75, system="Darwin", sysctl=lambda name: vals[name])


def test_macos_swap_over_threshold():
    # the reading at the time of last night's kill
    hm = _darwin("total = 9216.00M  used = 7672.56M  free = 1543.44M  (encrypted)")
    assert hm.pressure() == "swap 83% used"


def test_macos_pressure_level():
    assert _darwin("total = 9216.00M  used = 100.00M  free = 9116.00M", level="4").pressure() == "OS memory pressure level 4"
    assert _darwin("total = 9216.00M  used = 100.00M  free = 9116.00M").pressure() is None


def test_macos_no_swap_configured():
    assert _darwin("total = 0.00M  used = 0.00M  free = 0.00M").pressure() is None


def _linux(meminfo, psi=None):
    files = {"/proc/meminfo": meminfo}
    if psi is not None:
        files["/proc/pressure/memory"] = psi

    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]
    return hostmem.HostMemory(75, system="Linux", read=read)


_OK = "MemTotal: 100000 kB\nMemAvailable: 50000 kB\nSwapTotal: 1000 kB\nSwapFree: 900 kB\n"


def test_linux_checks():
    assert _linux(_OK).pressure() is None
    assert _linux("MemTotal: 100000 kB\nMemAvailable: 5000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").pressure() == "available memory 5%"
    assert _linux("MemTotal: 100000 kB\nMemAvailable: 50000 kB\nSwapTotal: 1000 kB\nSwapFree: 100 kB\n").pressure() == "swap 90% used"
    assert _linux(_OK, "some avg10=12.50 avg60=3.00 avg300=1.00 total=1\n").pressure() == "memory pressure (PSI some avg10=12.5)"


def test_unsupported_platform_is_inactive_not_an_error():
    hm = hostmem.HostMemory(75, system="Windows")
    assert hm.pressure() is None and hm.pressure() is None


def test_for_config_auto_only_for_loopback():
    base = Config()
    at = lambda url, **kw: dataclasses.replace(base, reviewer=dataclasses.replace(base.reviewer, base_url=url, **kw))
    assert hostmem.for_config(at("http://127.0.0.1:8000/v1")) is not None
    assert hostmem.for_config(at("http://localhost:8000/v1")) is not None
    assert hostmem.for_config(at("http://192.168.68.63:8000/v1")) is None
    assert hostmem.for_config(at("http://192.168.68.63:8000/v1", host_memory_guard=True)) is not None
    assert hostmem.for_config(at("http://127.0.0.1:8000/v1", host_memory_guard=False)) is None
```

Append to `tests/test_guard.py`:

```python
class _Mem:
    def __init__(self, why):
        self.why = why

    def pressure(self):
        return self.why


def test_host_memory_pressure_defers_reviews(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    mem = _Mem("swap 83% used")
    gd = g.ReviewerGuard(cfg, Backend(Clock()), conn, clock=Clock(), memory=mem, out=lambda m: None)
    assert gd.admit() == "host memory: swap 83% used"
    mem.why = None
    assert gd.admit() is None
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/test_hostmem.py tests/test_guard.py -q` — Expected: FAIL (`No module named 'npmdiffwatch.hostmem'`).

- [ ] **Step 3: Implement**

Add to `ReviewerConfig`, after `degraded_pause_s`:

```python
    host_memory_guard: str | bool = "auto"   # "auto": on when the endpoint is on this machine (loopback)
    max_swap_used_pct: float = 75.0          # pause reviews at or above this swap use
```

Create `npmdiffwatch/hostmem.py`:

```python
"""Memory pressure on this machine, for a model server running here. Standard library only: a supply-chain
scanner shouldn't take on a dependency (psutil) for this. macOS: sysctl. Linux: /proc."""
import ipaddress
import logging
import platform
import re
import subprocess
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def _sysctl(name):
    return subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, timeout=5).stdout.strip()


def _read(path):
    with open(path) as f:
        return f.read()


class HostMemory:
    def __init__(self, max_swap_used_pct, *, system=None, sysctl=_sysctl, read=_read):
        self.max_swap = max_swap_used_pct
        self.system = system or platform.system()
        self.sysctl, self.read = sysctl, read
        self._noticed = False

    def pressure(self):
        """A short reason when this machine is short on memory, else None."""
        try:
            if self.system == "Darwin":
                return self._darwin()
            if self.system == "Linux":
                return self._linux()
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            logger.warning("host memory check failed: %s", e)
            return None
        if not self._noticed:
            logger.warning("host memory guard is not supported on %s; it is inactive", self.system)
            self._noticed = True
        return None

    def _darwin(self):
        # vm.swapusage: "total = 9216.00M  used = 7672.56M  free = 1543.44M  (encrypted)"
        f = dict(re.findall(r"(total|used) = ([\d.]+)M", self.sysctl("vm.swapusage")))
        total, used = float(f.get("total", 0)), float(f.get("used", 0))
        if total and 100 * used / total >= self.max_swap:
            return f"swap {100 * used / total:.0f}% used"
        level = int(self.sysctl("kern.memorystatus_vm_pressure_level") or 1)
        return f"OS memory pressure level {level}" if level >= 2 else None

    def _linux(self):
        info = {k.strip(): int(v.split()[0]) for k, v in
                (line.split(":", 1) for line in self.read("/proc/meminfo").splitlines() if ":" in line)}
        st, sf = info.get("SwapTotal", 0), info.get("SwapFree", 0)
        if st and 100 * (st - sf) / st >= self.max_swap:
            return f"swap {100 * (st - sf) / st:.0f}% used"
        if info.get("MemTotal") and info.get("MemAvailable", 0) < 0.10 * info["MemTotal"]:
            return f"available memory {100 * info['MemAvailable'] / info['MemTotal']:.0f}%"
        try:
            some = self.read("/proc/pressure/memory").splitlines()[0]
        except OSError:
            return None
        avg10 = float(re.search(r"avg10=([\d.]+)", some).group(1))
        return f"memory pressure (PSI some avg10={avg10:.1f})" if avg10 >= 10 else None


def is_loopback(base_url):
    host = urlsplit(base_url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def for_config(cfg):
    """The HostMemory to consult for this reviewer, or None when the model isn't on this machine."""
    rc = cfg.reviewer
    on = rc.host_memory_guard
    if on == "auto":
        on = rc.provider == "openai" and is_loopback(rc.base_url)
    return HostMemory(rc.max_swap_used_pct) if on is True else None
```

In `npmdiffwatch/guard.py`: add `from . import hostmem` to the imports, change the constructor signature to `memory="auto"`, and replace `self.memory = memory` (it's inside the combined assignment) with a separate line after it:

```python
        self.memory = hostmem.for_config(cfg) if memory == "auto" else memory
```

(Remove `memory` from the combined `self.cfg, ... = ...` assignment tuple.)

- [ ] **Step 4: Run** `python -m pytest -q && ruff check npmdiffwatch/hostmem.py npmdiffwatch/guard.py tests/test_hostmem.py` — Expected: all pass, clean.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/hostmem.py npmdiffwatch/guard.py npmdiffwatch/config.py tests/test_hostmem.py tests/test_guard.py
git commit -m "feat(guard): pause reviews while a local model's host is short on memory (stdlib only)"
```

---

### Task 6: Wire the guard into the review path

**Files:**
- Modify: `npmdiffwatch/reviewer.py` (`Reviewer.prepare(diff, triage, cap=None)`)
- Modify: `npmdiffwatch/orchestrator.py` (imports; `_is_timeout`; `_attempt_review`; `_review_escalated`; `drain_pending`; `_process_fetched` signature; `run_once`; `review_pending`)
- Test: `tests/test_guard_wiring.py`

**Interfaces:**
- Consumes: Tasks 1–5 (`ReviewerGuard`, `backend.last_usage`).
- Produces: queue reason `model_busy`; `_attempt_review(..., guard=None)`, `_review_escalated(..., offline=False, guard=None)`, `drain_pending(..., guard=None)`, `_process_fetched(..., offline=False, guard=None)`. With `guard=None` everything behaves as today (existing tests unchanged).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_guard_wiring.py
"""The orchestrator asks the guard before every review and reports every outcome."""
import dataclasses
from pathlib import Path
from types import SimpleNamespace

from npmdiffwatch import fetcher, guard as g, ingest, orchestrator, reviewer, store
from npmdiffwatch.config import Config
from npmdiffwatch.ingest import ChangesPage
from npmdiffwatch.models import Diff, FileDiff, FiredRule, Hunk, NewRelease, TriageResult

_OK = ('{"classification":"benign","confidence":0.9,"urgent":false,"recommended_action":"monitor",'
       '"attack_type":"none","cited_hunk":"","reasoning":"r"}')


class Backend:
    primary_model, escalation_model = "m", None

    def __init__(self, hang=False, usage=None, ping_ok=True):
        self.hang, self.usage, self.ping_ok, self.calls, self.pings = hang, usage, ping_ok, 0, 0
        self.last_usage = None

    def complete(self, **kw):
        self.calls += 1
        if self.hang:
            raise reviewer.ReviewUnavailable("could not reach reviewer endpoint (timed out)") from TimeoutError("timed out")
        self.last_usage = self.usage
        return _OK

    def ping(self, text, *, timeout):
        self.pings += 1
        if not self.ping_ok:
            raise reviewer.ReviewUnavailable("still busy") from TimeoutError("timed out")
        return {"prompt_tokens": 1000, "completion_tokens": 1}

    def context_length(self):
        return None


def _cfg(tmp_path, **rv):
    c = dataclasses.replace(Config(), db_path=tmp_path / "db.sqlite", lock_path=tmp_path / "l",
                            cache_dir=tmp_path / "c", rules_dir=Path("rules/community"))
    return dataclasses.replace(c, reviewer=dataclasses.replace(c.reviewer, host_memory_guard=False, **rv))


def _diff(pkg, body="eval(x)"):
    return Diff(package=pkg, version="1.0.0", is_first_release=False, added_binaries=[],
                changed=[FileDiff("a.js", "modified", [Hunk((0, 1), (0, 1), [body], [])])])


_T = TriageResult(score=60.0, escalate=True, fired_rules=[FiredRule("js-eval", 60.0, "a.js", (1, 1))])


def _setup(tmp_path, be, **rv):
    cfg = _cfg(tmp_path, **rv)
    conn = store.connect(cfg); store.init_schema(conn)
    gd = g.ReviewerGuard(cfg, be, conn, memory=None, out=lambda m: None)
    gd.tok_s = 1000.0
    return cfg, conn, gd, reviewer.Reviewer(cfg, backend=be)


def _reasons(conn):
    return {r["package"]: r["pending_reason"] for r in store.pending_reviews(conn)}


def test_timeout_parks_the_rest_of_the_batch_as_model_busy(tmp_path):
    be = Backend(hang=True)
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    for i, pkg in enumerate(["a", "b", "c"]):
        rid = store.record_release(conn, pkg, "1.0.0", i, False, None, "tgz")
        orchestrator._review_escalated(cfg, conn, rvw, _diff(pkg), _T, rid, guard=gd)
    assert be.calls == 1                                           # only the first one reached the model
    assert _reasons(conn) == {"a": "review_failed", "b": "model_busy", "c": "model_busy"}
    assert store.review_attempts(conn, 2) == 0                     # model_busy spends no attempt


def test_next_batch_probes_then_drains_model_busy_first(tmp_path):
    be = Backend(hang=True)
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    for i, pkg in enumerate(["a", "b"]):
        rid = store.record_release(conn, pkg, "1.0.0", i, False, None, "tgz")
        orchestrator._review_escalated(cfg, conn, rvw, _diff(pkg), _T, rid, guard=gd)
    be.hang = False
    gd2 = g.ReviewerGuard(cfg, be, conn, memory=None, out=lambda m: None)
    gd2.begin_batch()
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, limit=1, guard=gd2)
    assert be.pings >= 1 and "b" not in _reasons(conn)              # model_busy "b" went before review_failed "a"


def test_success_feeds_the_speed_measurement(tmp_path):
    be = Backend(usage={"prompt_tokens": 10_000, "completion_tokens": 50})
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.tok_s = None
    rid = store.record_release(conn, "a", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("a"), _T, rid, guard=gd)
    assert gd.tok_s is not None and store.get_reviewer_stats(conn, cfg.reviewer.base_url, "qwen-singleshot")["samples"] == 1


def test_input_over_the_endpoint_cap_is_too_large_with_the_measured_speed(tmp_path):
    be = Backend()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    gd.tok_s = 85.0                                                 # cap ≈ 52k chars
    rid = store.record_release(conn, "big", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("big", "x" * 100_000), _T, rid, guard=gd)
    [row] = store.pending_reviews(conn)
    assert be.calls == 0 and row["pending_reason"] == "too_large" and "85 tok/s" in row["pending_detail"]


def test_auto_drain_reparks_rows_over_the_endpoint_cap_as_too_large(tmp_path):
    be = Backend()
    cfg, conn, gd, rvw = _setup(tmp_path, be)
    rid = store.record_release(conn, "old", "1.0.0", 1, False, None, "tgz")
    orchestrator._review_escalated(cfg, conn, rvw, _diff("old", "x" * 100_000), _T, rid, offline=True)  # parked at 200k cap
    gd.tok_s = 85.0
    orchestrator.drain_pending(cfg, conn, rvw, auto=True, guard=gd)
    assert be.calls == 0 and _reasons(conn) == {"old": "too_large"}


def test_hung_endpoint_costs_one_timeout_and_the_cursor_advances(tmp_path, monkeypatch):
    be = Backend(hang=True, ping_ok=False)
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn); store.set_last_serial(conn, 5000); conn.close()
    rels = [NewRelease(p, "1.0.0", 5001 + i) for i, p in enumerate(["a", "b", "c"])]
    monkeypatch.setattr(ingest, "changes_since", lambda *a, **k: ChangesPage(releases=rels, watermark=5100))
    art = SimpleNamespace(prior_version="0.9.0", is_new_package=False, maintainer_metadata=None,
                          scripts_field=None, has_lockfile=False, has_shrinkwrap=False)
    monkeypatch.setattr(fetcher, "fetch_artifacts", lambda cfg, rel: art)
    monkeypatch.setattr(orchestrator.differ, "build_diff", lambda a: _diff("x"))
    monkeypatch.setattr(orchestrator.engine, "triage", lambda *a, **k: _T)
    monkeypatch.setattr(orchestrator, "_probe_reviewer", lambda cfg: (True, "127.0.0.1:8000"))
    monkeypatch.setattr(orchestrator, "_build_reviewer", lambda cfg: reviewer.Reviewer(cfg, backend=be))
    conn = store.connect(cfg)
    store.save_reviewer_stats(conn, cfg.reviewer.base_url, cfg.reviewer.model, tok_s=1000.0, chars_per_token=3.4,
                              samples=1, state="closed", detail="", paused_until=0.0, slow_streak=0)
    conn.close()
    orchestrator.run_once(cfg, seed_if_fresh=False)
    assert be.calls == 1
    orchestrator.run_once(cfg, seed_if_fresh=False)               # next batch: probe fails -> nothing sent
    assert be.calls == 1
    conn = store.connect(cfg)
    assert store.get_last_serial(conn) == 5100
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/test_guard_wiring.py -q` — Expected: FAIL (`unexpected keyword argument 'guard'`).

- [ ] **Step 3: Implement**

`npmdiffwatch/reviewer.py`: change `prepare`'s signature and first line:

```python
    def prepare(self, diff, triage, cap=None) -> str:
        """Build the review input, or raise InputTooLarge if the highest-risk file can't fit in `cap`
        (default: max_input_chars; the guard passes the endpoint's measured cap)."""
        cap = cap or self.cfg.reviewer.max_input_chars
```

(delete the old `cap = self.cfg.reviewer.max_input_chars` line).

`npmdiffwatch/orchestrator.py`:

Imports: add `import time` next to `import os`, and `guard as guard_mod` to the `from . import ...` line.

Add after `_endpoint_down`:

```python
def _is_timeout(e) -> bool:
    cause = e.__cause__
    reason = getattr(cause, "reason", cause)
    return isinstance(reason, TimeoutError) or type(cause).__name__ == "APITimeoutError"
```

Replace `_attempt_review` with:

```python
def _attempt_review(cfg, conn, rvw, rid, package, version, score, fired_rules, text, guard=None) -> bool:
    """One review attempt; on failure the release is (re)parked with the reason. Returns False when no more
    reviews should be sent now (endpoint unreachable, guard deferring, or the guard's breaker just opened),
    so a drain stops instead of hammering the server."""
    if guard is not None:
        why = guard.admit()
        if why:
            store.park_for_review(conn, rid, "model_busy", why, text)
            return False
    attempt = store.review_attempts(conn, rid) + 1
    t0 = time.monotonic()
    try:
        verdict = rvw.review_text(package, version, score, fired_rules, text, attempt=attempt)
    except reviewer.ReviewUnavailable as e:
        logger.warning("LLM review failed for %s==%s (attempt %d): %s", package, version, attempt, e)
        if _endpoint_down(e):     # an outage, not this release's fault: don't spend an attempt
            store.park_for_review(conn, rid, "endpoint_unreachable", str(e), text)
            return False
        n = store.bump_review_attempts(conn, rid)
        store.park_for_review(conn, rid, "review_failed", f"{n} failed attempt(s): {e}", text)
        if guard is not None and _is_timeout(e):
            guard.record_timeout()
            return False
        return True
    if guard is not None:
        guard.record_success(getattr(rvw.backend, "last_usage", None), time.monotonic() - t0, len(text))
    _record(cfg, conn, rid, verdict, score)
    return True
```

In `_review_escalated`: change the signature to `def _review_escalated(cfg, conn, rvw, d, tr, rid, *, offline=False, guard=None):`, and replace the `try: text = rvw.prepare(d, tr) ... else:` block with:

```python
    try:
        text = rvw.prepare(d, tr, cap=guard.input_cap_chars() if guard is not None else None)
    except reviewer.InputTooLarge as e:
        detail = f"{e}; {guard.cap_explain()}" if guard is not None else str(e)
        store.park_for_review(conn, rid, "too_large", detail, e.text)
    else:
        if offline:
            store.park_for_review(conn, rid, "endpoint_unreachable", "reviewer endpoint unreachable", text)
        else:
            _attempt_review(cfg, conn, rvw, rid, d.package, d.version, tr.score, tr.fired_rules, text, guard)
```

Replace `drain_pending` with:

```python
def drain_pending(cfg, conn, rvw, *, auto: bool, reasons=None, limit=None, guard=None) -> int:
    """Review parked releases. auto (each tick): model_busy first, then unreachable-endpoint parks and failed
    reviews with attempts left. Manual (`review-pending`): by default oversized releases and exhausted
    retries — run it with a larger-context model config. Inputs over this endpoint's cap are skipped
    (auto: re-parked as too_large). `limit` caps attempts, not successes. Returns the number reviewed."""
    if auto:
        reasons = ("model_busy", "endpoint_unreachable", "review_failed")
    elif not reasons:
        reasons = ("too_large", "review_failed")
    cap = guard.input_cap_chars() if guard is not None else cfg.reviewer.max_input_chars
    rows = sorted(store.pending_reviews(conn, reasons),
                  key=lambda r: (r["pending_reason"] != "model_busy", r["release_id"]))
    done = tried = 0
    for row in rows:
        if limit is not None and tried >= limit:
            break
        if auto and row["pending_reason"] == "review_failed" and \
                row["review_attempts"] >= cfg.reviewer.max_review_attempts:
            continue
        text = store.review_input(row)
        rid = row["release_id"]
        if len(text) > cap:
            if auto:
                explain = guard.cap_explain() if guard is not None else f"cap {cap}"
                store.park_for_review(conn, rid, "too_large", f"needs {len(text)} chars; {explain}", text)
            continue
        tried += 1
        if not _attempt_review(cfg, conn, rvw, rid, row["package"], row["version"], row["triage_score"],
                               _rules_from_json(row["triage_rules"]), reviewer.refresh_marker(text), guard):
            break
        if store.get_stage(conn, row["package"], row["version"]) != "pending_review":
            done += 1
    return done
```

`_process_fetched`: signature `def _process_fetched(cfg, conn, rvw, ruleset, rel, result, offline=False, guard=None) -> bool:` and its call becomes `_review_escalated(cfg, conn, rvw, d, tr, rid, offline=offline, guard=guard)`.

`run_once`: replace the block from `offline = False` through the `drain_pending(...)` call with:

```python
        offline = False
        guard = None
        if rvw is not None:
            reachable, label = _probe_reviewer(cfg)
            offline = reachable is False
            if offline:
                waiting = sum(store.pending_review_counts(conn).values())
                msg = (f"[npmdiffwatch] WARNING: reviewer endpoint {label} is unreachable. Scanning continues; "
                       f"flagged releases are queued for LLM review ({waiting} waiting). Start the model "
                       f"server, or point [reviewer] at a reachable endpoint or a remote provider.")
                print(msg, flush=True)
                logger.warning(msg)
            else:
                guard = guard_mod.ReviewerGuard(cfg, rvw.backend, conn)
                guard.begin_batch()
                drain_pending(cfg, conn, rvw, auto=True, limit=cfg.reviewer.max_pending_per_tick, guard=guard)
```

and the `_process_fetched(...)` call in the fetch loop becomes `_process_fetched(cfg, conn, rvw, ruleset, rel, futs[i].result(), offline, guard)`.

`review_pending`: replace `n = drain_pending(cfg, conn, rvw, auto=False, reasons=reasons, limit=limit)` with:

```python
        gd = guard_mod.ReviewerGuard(cfg, rvw.backend, conn)
        gd.begin_batch()
        n = drain_pending(cfg, conn, rvw, auto=False, reasons=reasons, limit=limit, guard=gd)
```

- [ ] **Step 4: Run** `python -m pytest -q && ruff check npmdiffwatch/ tests/test_guard_wiring.py` — Expected: all pass, clean. If `test_hung_endpoint...` fails on its first `run_once` because the guard is left open from calibration, check that stats were seeded (`tok_s=1000`) so no calibration runs.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/reviewer.py npmdiffwatch/orchestrator.py tests/test_guard_wiring.py
git commit -m "feat(orchestrator): ask the reviewer guard before every review; park deferrals as model_busy"
```

---

### Task 7: Show the guard's state in `pending` and the dashboard

**Files:**
- Modify: `npmdiffwatch/orchestrator.py` (add `guard_status`; `export_dashboard` status)
- Modify: `npmdiffwatch/dashboard.py` (`_status_strip`)
- Modify: `npmdiffwatch/__main__.py` (`pending` prints the guard line)
- Test: `tests/test_dashboard.py` (append), `tests/test_guard_wiring.py` (append)

**Interfaces:**
- Consumes: `ReviewerGuard(...).status()`, `guard.describe(status)`.
- Produces: `orchestrator.guard_status(cfg) -> dict | None`; `status["guard"]` in `export_dashboard`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_dashboard.py`:

```python
def test_render_shows_reviewer_guard_state():
    html = dashboard.render_dashboard([], status=_status(guard={
        "state": "open", "detail": "breaker open after timeout", "tok_s": 85.0, "cap_chars": 52020,
        "host_memory": "swap 83% used"}))
    assert "reviews paused (timeout)" in html and "85 tok/s" in html and "52,020" in html
    assert "swap 83% used" in html
```

Append to `tests/test_guard_wiring.py`:

```python
def test_guard_status_reads_stored_stats(tmp_path):
    cfg = _cfg(tmp_path)
    conn = store.connect(cfg); store.init_schema(conn)
    store.save_reviewer_stats(conn, cfg.reviewer.base_url, cfg.reviewer.model, tok_s=85.0, chars_per_token=3.4,
                              samples=3, state="degraded", detail="degraded", paused_until=0.0, slow_streak=2)
    conn.close()
    st = orchestrator.guard_status(cfg)
    assert st["state"] == "degraded" and st["tok_s"] == 85.0 and st["cap_chars"] < 60_000
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/test_dashboard.py tests/test_guard_wiring.py -q` — Expected: FAIL (no `guard_status`; guard not rendered).

- [ ] **Step 3: Implement**

`npmdiffwatch/orchestrator.py`, add before `export_dashboard`:

```python
def guard_status(cfg: Config):
    """The reviewer guard's view of the endpoint (breaker, measured speed, input cap) from stored stats;
    sends nothing to the endpoint. None when the reviewer is disabled."""
    if not cfg.reviewer_enabled:
        return None
    conn = store.connect(cfg); store.init_schema(conn)
    try:
        return guard_mod.ReviewerGuard(cfg, None, conn).status()
    finally:
        conn.close()
```

In `export_dashboard`, add to the `status = {...}` dict: `"guard": guard_status(cfg),`.

`npmdiffwatch/dashboard.py`: add `from . import guard as guard_mod` to the imports. In `_status_strip`, after the `pending_txt = ...` lines add:

```python
    g = status.get("guard")
    guard_txt = guard_mod.describe(g) if g else ""
```

and add after the pending-review span line (before `</div>`):

```python
{f'  <span class="stat">{e(guard_txt)}</span>' + chr(10) if guard_txt else ''}
```

`npmdiffwatch/__main__.py`: import `guard_status` from `.orchestrator` and `describe` via `from .guard import describe`. In the `pending` branch, before `queued = pending_review_counts(cfg)`:

```python
        gs = guard_status(cfg)
        if gs:
            print(f"[npmdiffwatch] reviewer: {describe(gs)}")
```

- [ ] **Step 4: Run** `python -m pytest -q && ruff check npmdiffwatch/ tests/test_dashboard.py tests/test_guard_wiring.py` — Expected: all pass, clean.

- [ ] **Step 5: Commit**

```bash
git add npmdiffwatch/orchestrator.py npmdiffwatch/dashboard.py npmdiffwatch/__main__.py tests/test_dashboard.py tests/test_guard_wiring.py
git commit -m "feat(status): show breaker state, measured speed and input cap in pending and the dashboard"
```

---

### Task 8: Docs: model protection and "Size your model server"

**Files:**
- Modify: `GETTING-STARTED.md` (queue table gains `model_busy`; new section "Size your model server"; new config keys)
- Create: `examples/llama-swap.toml`

- [ ] **Step 1: Edit the queue table** in GETTING-STARTED §5: add this row at the top of the table:

```markdown
| `model_busy` | the reviewer guard deferred it: breaker open after a timeout, the model degrading, or this machine short on memory | every tick, first, once the guard allows reviews |
```

- [ ] **Step 2: Add a section** after the `review-pending` paragraph, titled `**Model protection.**`:

```markdown
**Model protection.** The reviewer measures your endpoint and adapts to it, so a slow or struggling
model server isn't overloaded:

- **Input size from measured speed.** The tool records how fast the endpoint reads input (from the token
  counts it reports) and caps each review input at `speed × timeout × budget_safety`. Bigger inputs go
  to the `too_large` queue. Until the first measurement, a new endpoint gets one small calibration request
  (filler text, never package content) and a 40,000-char cap.
- **Circuit breaker.** After a timeout, no more reviews are sent that batch; the next batch sends a tiny
  health probe first and resumes only if it answers within `probe_timeout`.
- **Slowdown detector.** Two reviews in a row below `slowdown_ratio` of the measured speed pause reviews
  for `degraded_pause_s` and print a warning — usually the model server is swapping; restart it.
- **Host memory guard.** When the model runs on this machine, reviews pause while swap use is at or above
  `max_swap_used_pct` or the OS reports memory pressure.

`pending` and the dashboard show the current state, e.g. `reviews on · 85 tok/s · input cap 52,020 chars`.

**Size your model server.** Only the server can limit its own memory. Set its context window to what you
need and serve one request at a time:

| runtime | settings |
|---|---|
| llama.cpp | `-c <ctx>` `--parallel 1`; optional `-ctk q8_0 -ctv q8_0` halves KV-cache memory |
| llama-swap | put the llama.cpp flags in the model's `cmd:`; the first request after an unload waits for the model to load (covered by `probe_timeout`) |
| vLLM | `--max-model-len <ctx>` `--max-num-seqs 1` `--gpu-memory-utilization 0.9` |
| Ollama | `num_ctx` in the Modelfile, `OLLAMA_NUM_PARALLEL=1` |
| any reasoning model | turn thinking off (`chat_template_kwargs = { enable_thinking = false }`); reviews ran 1.6–4.4× faster with the same verdicts |
```

- [ ] **Step 3: Document the keys** in the config reference near the `[reviewer]` examples in §2, as a TOML block:

```toml
# Model protection (all optional; defaults shown)
budget_safety = 0.6          # a review may be predicted to use at most this share of `timeout`
probe_timeout = 60.0         # health probe / calibration timeout
slowdown_ratio = 0.3         # below this share of measured speed counts as slow
degraded_pause_s = 900       # pause after two slow reviews in a row
host_memory_guard = "auto"   # on for loopback endpoints; true / false to force
max_swap_used_pct = 75
```

- [ ] **Step 4: Create `examples/llama-swap.toml`**

```toml
# NpmDiffWatch against llama-swap on another machine (e.g. a GPU box on the LAN).
# llama-swap loads a model on its first request; probe_timeout covers that wait.
# `model` must be one of the ids at http://<host>:8000/v1/models.

[reviewer]
provider = "openai"
base_url = "http://192.168.1.50:8000/v1"
model = "gemma-singleshot"
structured_output = "json_schema"
timeout = 300.0

[reviewer.extra_body]
chat_template_kwargs = { enable_thinking = false }
```

- [ ] **Step 5: Verify and commit**

Run: `python -c "from npmdiffwatch.config import load_config; c=load_config('examples/llama-swap.toml'); print(c.reviewer.model, c.reviewer.extra_body)"`
Expected: `gemma-singleshot {'chat_template_kwargs': {'enable_thinking': False}}`

```bash
git add GETTING-STARTED.md examples/llama-swap.toml
git commit -m "docs: model protection and sizing your model server; llama-swap example"
```

---

### Task 9: Live test against Gemma on the RTX llama-swap, then PR

No code. Verifies the success criteria on the real endpoint (`192.168.68.63:8000`).

- [ ] **Step 1: Confirm the model id with the user** (llama-swap lists `gemma-singleshot`, `gemma-2/4/8-slots`, …). Use the single-slot id for Gemma 4 12B.

- [ ] **Step 2: Config and fresh DB**

```bash
mkdir -p .diffwatch-rtx
cat > .diffwatch-rtx/npmdiffwatch.toml <<'EOF'
db_path = ".diffwatch-rtx/diffwatch.sqlite"
lock_path = ".diffwatch-rtx/diffwatch.lock"

[reviewer]
provider = "openai"
base_url = "http://192.168.68.63:8000/v1"
model = "<confirmed id>"
structured_output = "json_schema"
timeout = 300.0

[reviewer.extra_body]
chat_template_kwargs = { enable_thinking = false }
EOF
python -m npmdiffwatch -c .diffwatch-rtx/npmdiffwatch.toml seed-now
```

- [ ] **Step 3: One tick in the foreground.** Expect the calibration line (`reads ~N tokens/s; review inputs capped at …`) and no egress denial for `192.168.68.63`.

Run: `python -m npmdiffwatch -c .diffwatch-rtx/npmdiffwatch.toml run`

- [ ] **Step 4: Run `watch` for 60 minutes** with the dashboard, then check: `pending` shows the guard line; `reviewer_stats.tok_s` is set; no review took longer than `timeout`, and **the 0.6 margin holds**: the slowest review is under 60% of `timeout` (`sqlite3 … "select max(...)"` is not stored, so check `watch.log` timings and `timed out` lines; expect none); cursor advanced every tick; the machine's swap unchanged (the model is remote).

- [ ] **Step 5: Report the numbers to the user** (tok/s, cap, reviews/hour, verdict mix, lag), stop `watch`, then push the branch and open the PR (body: spec + plan links, test counts, live-test numbers).
