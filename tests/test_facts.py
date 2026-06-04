"""JS/TS fact extraction via tree-sitter: behavioral categories from added
code, location weighting, and high-entropy blob detection."""
from npmdiffwatch.models import ArtifactSet
from npmdiffwatch import differ, facts


def _facts_for(new_files, prior_files=None):
    a = ArtifactSet("p", "1.0.0", None if prior_files is None else "0.9.0", "tgz",
                    new_files, prior_files or {}, {})
    return facts.build_facts(differ.build_diff(a))


def _file(df, path="index.js"):
    return next(f for f in df.files if f.path == path)


def test_detects_exec_and_process_categories():
    src = (b"eval(userInput);\n"
           b"const cp = require('child_process');\n"
           b"cp.exec(cmd);\n")
    ff = _file(_facts_for({"index.js": src}))
    assert "exec" in ff.bound_categories       # eval(...)
    assert "process" in ff.bound_categories    # cp.exec


def test_detects_file_and_decode_categories():
    src = (b"const fs = require('fs');\n"
           b"fs.writeFileSync(p, d);\n"
           b"Buffer.from(s, 'base64');\n")
    ff = _file(_facts_for({"index.js": src}))
    assert "file" in ff.bound_categories
    assert "decode" in ff.bound_categories


def test_detects_prototype_pollution():
    ff = _file(_facts_for({"index.js": b"obj.__proto__ = payload;\n"}))
    assert "proto" in ff.bound_categories


def test_high_entropy_blob_flagged():
    blob = b"const payload = '" + b"A1b2C3d4E5f6G7h8" * 16 + b"';\n"
    ff = _file(_facts_for({"index.js": blob}))
    assert ff.blob_present is True


def test_classify_location_weights():
    assert facts.classify_location("postinstall.js") == 3.0
    assert facts.classify_location("lib/test/foo.js") == 0.2
    assert facts.classify_location("lib/util.js") == 1.0


def test_credential_via_process_env_member():
    ff = _file(_facts_for({"index.js": b"const t = process.env.NPM_TOKEN;\n"}))
    assert "credential" in ff.bound_categories


def test_dynamic_require_bare_call():
    ff = _file(_facts_for({"index.js": b"require(modName);\n"}))
    assert "dynamic_require" in ff.bound_categories


def test_dynamic_import_call():
    ff = _file(_facts_for({"index.js": b"import(modName);\n"}))
    assert "dynamic_require" in ff.bound_categories


def test_literal_require_is_not_dynamic():
    ff = _file(_facts_for({"index.js": b"const lib = require('lodash');\n"}))
    assert "dynamic_require" not in ff.bound_categories


def test_literal_import_is_not_dynamic():
    ff = _file(_facts_for({"index.js": b"import('node:fs');\n"}))
    assert "dynamic_require" not in ff.bound_categories
