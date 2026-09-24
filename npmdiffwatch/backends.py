import json
import logging
import urllib.request

from . import egress

logger = logging.getLogger(__name__)


class ReviewUnavailable(Exception):
    pass


def _urllib_post_json(url: str, payload: dict, timeout: float, headers: dict | None = None) -> dict:
    egress.assert_web_scheme(url)
    body = json.dumps(payload).encode()
    # Explicit UA: paid OpenAI-compatible APIs (DeepSeek, etc.) front Cloudflare,
    # which blocks the default "Python-urllib/x.y". Caller headers may override.
    hdrs = {"User-Agent": "npmdiffwatch/0.1", "Content-Type": "application/json",
            **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


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
    timings = data.get("timings") or {}
    pps = timings.get("prompt_per_second")
    if isinstance(pps, (int, float)) and pps > 0:
        out["prompt_per_second"] = float(pps)
        if isinstance(timings.get("prompt_n"), int):
            out["prompt_n"] = timings["prompt_n"]     # tokens actually read; the rest came from the prompt cache
    return out


def validate_verdict(parsed, schema):
    """Validate and repair a model verdict. A property with a `default` is
    non-critical: if a reasoning model truncates it, fill the default; if its
    value is out of enum, coerce to the default. A property without a `default`
    is critical (classification): missing or out-of-enum fails the review, so
    truncation/garbage falls back to the conservative heuristic alert rather than
    silently passing as benign."""
    if not isinstance(parsed, dict):
        raise ReviewUnavailable(f"verdict is not a JSON object (got {type(parsed).__name__}): the model "
                                f"returned malformed output; lower structured_output or use a stronger model.")
    out = dict(parsed)
    for key, spec in schema.get("properties", {}).items():
        has_default = "default" in spec
        if key not in out:
            if has_default:
                out[key] = spec["default"]
            elif key in schema.get("required", []):
                raise ReviewUnavailable(f"verdict missing required key {key!r}: the model returned an "
                                        f"incomplete verdict, often truncated by a reasoning model. Raise "
                                        f"reviewer.max_output_tokens, or disable thinking via "
                                        f"[reviewer.extra_body].")
            continue
        if "enum" in spec and out[key] not in spec["enum"]:
            if has_default:
                out[key] = spec["default"]
            else:
                raise ReviewUnavailable(f"verdict {key}={out[key]!r} is not one of {spec['enum']}: the model "
                                        f"returned an out-of-contract value. Lower structured_output "
                                        f"(json_schema -> json_object -> none) or use a more capable model.")
    return out


def _egress_hint(e) -> str:
    """Turn a transport failure into a ReviewUnavailable message that points at the likely fix, so the
    operator isn't left with a bare 'HTTP Error 400'. `urllib`'s HTTPError carries a numeric `.code`."""
    base = str(e) or type(e).__name__
    code = getattr(e, "code", None)
    if code == 400:
        return (f"reviewer endpoint returned HTTP 400 ({base}): the request was rejected — many endpoints "
                f"(e.g. DeepSeek) reject the strict json_schema response_format. Set "
                f'structured_output = "json_object" in [reviewer] (see examples/deepseek.toml).')
    if code in (401, 403):
        return (f"reviewer endpoint returned HTTP {code} ({base}): auth failed or the client was blocked. "
                f"Check api_key_env names an env var that is set in this process and the key is valid.")
    if code == 404:
        return (f"reviewer endpoint returned HTTP 404 ({base}): check base_url (it usually ends in /v1) and "
                f"that the model name exists on this endpoint.")
    if code == 429:
        return f"reviewer endpoint returned HTTP 429 ({base}): rate-limited. Back off or raise reviewer.timeout."
    if code is not None:
        return f"reviewer endpoint returned HTTP {code} ({base})."
    if isinstance(e, OSError):    # URLError / connection refused / timeout (HTTPError has a code, above)
        return (f"could not reach reviewer endpoint ({base}): check base_url host/port and the trailing /v1, "
                f"and that the model server is running.")
    return base


class OpenAICompatibleBackend:
    def __init__(self, base_url, model, *, api_key_env=None, structured_output="json_schema",
                 escalation_model=None, post=None, get=None, timeout: float = 120.0, extra_body=None):
        self.endpoint = base_url.rstrip("/")
        self.primary_model = model
        self.escalation_model = escalation_model
        self.api_key_env = api_key_env
        self.structured_output = structured_output
        self._post = post if post is not None else _urllib_post_json
        self._get = get if get is not None else _urllib_get_json
        self.last_usage = None
        self._timeout = timeout
        # Provider-specific knobs (e.g. DeepSeek reasoning toggles) passed verbatim.
        self.extra_body = extra_body or {}

    def _auth_headers(self) -> dict:
        if not self.api_key_env:
            return {}
        import os
        key = os.environ.get(self.api_key_env)
        return {"Authorization": f"Bearer {key}"} if key else {}

    def complete(self, *, model, system, user_text, schema, max_tokens, timeout=None) -> str:
        self.last_usage = None
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user_text}],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        if self.structured_output == "json_schema":
            payload["response_format"] = {"type": "json_schema",
                                          "json_schema": {"name": "review", "strict": True, "schema": schema}}
        elif self.structured_output == "json_object":
            payload["response_format"] = {"type": "json_object"}
        if self.extra_body:
            payload.update(self.extra_body)
        try:
            data = self._post(f"{self.endpoint}/chat/completions", payload, timeout or self._timeout,
                              self._auth_headers())
        except Exception as e:                    # connection/timeout/HTTP -> fallback (with a fix hint)
            raise ReviewUnavailable(_egress_hint(e)) from e
        self.last_usage = _usage_of(data)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise ReviewUnavailable(f"malformed response: {e}") from e
        if not isinstance(content, str):
            raise ReviewUnavailable(f"non-string content: {content!r}")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as e:
            raise ReviewUnavailable(f"non-JSON content: {e}") from e
        # Return the repaired dict, not raw content, so filled defaults reach the caller.
        return json.dumps(validate_verdict(parsed, schema))


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


class AnthropicBackend:
    def __init__(self, model, escalation_model=None, *, client=None):
        self.primary_model = model
        self.escalation_model = escalation_model
        if client is None:
            import anthropic
            client = anthropic.Anthropic()
        self.client = client
        self.last_usage = None

    def complete(self, *, model, system, user_text, schema, max_tokens, timeout=None) -> str:
        import anthropic
        self.last_usage = None
        try:
            resp = self.client.messages.create(
                **({"timeout": timeout} if timeout else {}),
                model=model,
                max_tokens=max_tokens,
                thinking={"type": "adaptive"},
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                output_config={"format": {"type": "json_schema", "schema": schema}},
                messages=[{"role": "user", "content": user_text}],
            )
        except anthropic.APIError as e:
            raise ReviewUnavailable(str(e)) from e
        self.last_usage = _anthropic_usage(resp)
        text = next((b.text for b in resp.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            raise ReviewUnavailable("no text block in response")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ReviewUnavailable(f"non-JSON content: {e}") from e
        return json.dumps(validate_verdict(parsed, schema))

    def ping(self, user_text, *, timeout) -> dict | None:
        import anthropic
        try:
            resp = self.client.messages.create(model=self.primary_model, max_tokens=1, timeout=timeout,
                                               messages=[{"role": "user", "content": user_text}])
        except anthropic.APIError as e:
            raise ReviewUnavailable(str(e)) from e
        self.last_usage = _anthropic_usage(resp)
        return self.last_usage

    def context_length(self) -> int | None:
        return None


def _anthropic_usage(resp) -> dict | None:
    u = getattr(resp, "usage", None)
    return ({"prompt_tokens": u.input_tokens, "completion_tokens": u.output_tokens}
            if u is not None and isinstance(getattr(u, "input_tokens", None), int) else None)


def make_backend(cfg, client=None):
    rc = cfg.reviewer
    if rc.provider == "openai":
        return OpenAICompatibleBackend(rc.base_url, rc.model, api_key_env=rc.api_key_env,
                                       structured_output=rc.structured_output,
                                       escalation_model=rc.escalation_model, timeout=rc.timeout,
                                       extra_body=rc.extra_body)
    if rc.provider == "anthropic":
        return AnthropicBackend(rc.model, rc.escalation_model, client=client)
    raise ValueError(f"unknown reviewer provider: {rc.provider!r}")
