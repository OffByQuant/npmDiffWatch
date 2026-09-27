
from npmdiffwatch import backends
from npmdiffwatch.config import Config

TOOLS = [{"name": "read", "description": "d", "parameters": {"type": "object", "properties": {}, "required": []}}]


def test_openai_chat_sends_tools_and_parses_calls():
    sent = {}
    def post(url, payload, timeout, headers):
        sent.update(payload)
        return {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "read", "arguments": '{"path": "a.js"}'}},
            {"id": "c2", "type": "function", "function": {"name": "read", "arguments": "{not json"}}]}}]}
    b = backends.OpenAICompatibleBackend("http://h/v1", "m", post=post)
    r = b.chat(model="m", system="s", messages=[b.user_message("hi")], tools=TOOLS, max_tokens=10)
    assert sent["tools"][0]["function"]["name"] == "read" and "response_format" not in sent
    assert sent["messages"][0] == {"role": "system", "content": "s"}
    assert r.calls[0].arguments == {"path": "a.js"} and r.calls[1].error
    assert b.tool_results([("c1", "out")]) == [{"role": "tool", "tool_call_id": "c1", "content": "out"}]


class _Block:
    def __init__(self, **kw): self.__dict__.update(kw)


class _Client:
    def __init__(self): self.kw = None; self.messages = self
    def create(self, **kw):
        self.kw = kw
        return _Block(content=[_Block(type="thinking", thinking="t", signature="s"),
                               _Block(type="tool_use", id="u1", name="read", input={"path": "a.js"})],
                      usage=None)


def test_anthropic_chat_uses_input_schema_and_replays_all_blocks():
    c = _Client()
    b = backends.AnthropicBackend("m", client=c)
    r = b.chat(model="m", system="s", messages=[b.user_message("hi")], tools=TOOLS, max_tokens=10)
    assert c.kw["tools"][0]["input_schema"]["type"] == "object"
    assert r.calls[0].arguments == {"path": "a.js"}
    assert [blk.type for blk in r.assistant["content"]] == ["thinking", "tool_use"]
    assert b.tool_results([("u1", "out")]) == [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "u1", "content": "out"}]}]


def test_make_investigator_backend_uses_the_investigator_block():
    import dataclasses
    inv = dataclasses.replace(Config().investigator, base_url="http://x/v1", model="big")
    b = backends.make_investigator_backend(dataclasses.replace(Config(), investigator=inv))
    assert b.endpoint == "http://x/v1" and b.primary_model == "big"
