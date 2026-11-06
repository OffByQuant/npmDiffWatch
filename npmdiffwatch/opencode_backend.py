"""Model transport via a no-tools OpenCode child agent; Python owns the pipeline."""
import json
import logging
import os
import signal
import subprocess
import tempfile
import time

from .backends import InvalidModelOutput, ReviewUnavailable, validate_verdict

logger = logging.getLogger(__name__)


class OpencodeBackend:
    def __init__(self, model, escalation_model=None, *, timeout=300.0):
        self.primary_model, self.escalation_model = model, escalation_model
        self._timeout = timeout
        self.last_usage = None

    def _request(self, model, system, user_text, schema, max_tokens, timeout):
        self.last_usage = None
        env = os.environ.copy()
        import uuid
        agents_dir = os.path.expanduser("~/.config/opencode/agents")
        os.makedirs(agents_dir, exist_ok=True)
        agent_id = f"dw_{uuid.uuid4().hex[:12]}"
        agent_path = os.path.join(agents_dir, f"{agent_id}.md")
        agent_prompt = (system + '\nProduce one final JSON answer, without commentary. '
                        'Do not simulate further conversation turns.\nMatch this schema:\n'
                        + json.dumps(schema))
        agent_content = (f"---\ndescription: DiffWatch model transport\nmode: all\n"
                         f"permissions:\n  - action: \"*\"\n    resource: \"*\"\n    effect: deny\n---\n"
                         f"{agent_prompt}\n")
        with open(agent_path, "w") as f:
            f.write(agent_content)

        env.update(OPENCODE_DISABLE_PROJECT_CONFIG="1",
                   OPENCODE_DISABLE_CLAUDE_CODE="1", OPENCODE_DISABLE_EXTERNAL_SKILLS="1",
                   OPENCODE_DISABLE_AUTOCOMPACT="1", OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX=str(max_tokens))
        command = ["opencode", "run", "--standalone", "--model", model, "--agent", agent_id, "--format", "json"]
        # No project files/instructions or package files are accessible to the agent through tools. Stdin
        # avoids argv limits and never treats package text as a command or writes it to an attachment file.
        with tempfile.TemporaryDirectory(prefix="diffwatch-model-") as directory:
            try:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True, cwd=directory, env=env,
                                           start_new_session=True)
            except OSError as e:
                if os.path.exists(agent_path):
                    os.remove(agent_path)
                raise ReviewUnavailable(f"could not start opencode: {e}") from e
            try:
                cancel = getattr(self, "cancel_event", None)
                if cancel is None:
                    stdout, stderr = process.communicate(user_text, timeout=timeout or self._timeout)
                else:
                    deadline = time.monotonic() + (timeout or self._timeout)
                    payload = user_text
                    while True:
                        if cancel.is_set():
                            raise ReviewUnavailable("opencode review cancelled during shutdown")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command, timeout or self._timeout)
                        try:
                            stdout, stderr = process.communicate(payload, timeout=min(1.0, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            payload = None
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise ReviewUnavailable("opencode model request timed out") from TimeoutError()
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
            finally:
                if os.path.exists(agent_path):
                    try:
                        os.remove(agent_path)
                    except OSError:
                        pass
        if process.returncode:
            # Provider failures are emitted as stdout JSON events, often with empty stderr.
            for line in stdout.splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("type") == "error":
                    error = event.get("error") or {}
                    failure = ReviewUnavailable(f"opencode error: {str(error)[:1000]}")
                    if isinstance(error, dict):
                        failure.status_code = error.get("status")
                        failure.provider_error = error.get("type")
                        retry_ms = error.get("retryAfterMs")
                        if isinstance(retry_ms, (int, float)):
                            failure.retry_after_s = max(0, min(retry_ms / 1000, 3600))
                    raise failure
            raise ReviewUnavailable(f"opencode exited {process.returncode}: {stderr[:500]}")
        text = []
        try:
            for line in stdout.splitlines():
                event = json.loads(line)
                if event['type'] == 'error':
                    raise ReviewUnavailable(f"opencode error: {str(event.get('error'))[:500]}")
                if event['type'] == 'tool_use':
                    raise ReviewUnavailable("opencode attempted a native tool; only Python-managed tools are allowed")
                part = event.get('part') or {}
                if event['type'] == 'text':
                    phase = (part.get('metadata', {}).get('openai') or {}).get('phase')
                    if phase != 'commentary':
                        text.append(part['text'])
                    logger.info("opencode model=%s session=%s", model, event.get('sessionID'))
                elif event['type'] == 'step_finish' and isinstance(part.get('tokens'), dict):
                    tokens = part['tokens']
                    self.last_usage = {"prompt_tokens": tokens.get('input', 0),
                                       "completion_tokens": tokens.get('output', 0)}
            raw = ''.join(text).strip()
            if raw.startswith("```"):
                lines = raw.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                raw = '\n'.join(lines).strip()
        except (ValueError, KeyError, TypeError) as e:
            raise ReviewUnavailable(f"opencode returned malformed event stream: {e}") from e
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise InvalidModelOutput(f"opencode returned malformed JSON: {e}", raw_response=raw) from e

    def complete(self, *, model, system, user_text, schema, max_tokens, timeout=None):
        answer = self._request(model, system, user_text, schema, max_tokens, timeout)
        try:
            return json.dumps(validate_verdict(answer, schema))
        except InvalidModelOutput as error:
            error.raw_response = json.dumps(answer)
            raise

    def ping(self, user_text, *, timeout):
        self.complete(model=self.primary_model, system='Reply with {"ok":true}.', user_text=user_text,
                      schema={"type": "object", "properties": {"ok": {"enum": [True]}}, "required": ["ok"]},
                      max_tokens=32, timeout=timeout)
        return self.last_usage

    def context_length(self):
        return None
