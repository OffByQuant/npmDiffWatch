import json

from npmdiffwatch import execclass


def _pkg(**kw):
    return json.dumps({"name": "p", "version": "1.0.0", **kw}).encode()


def test_install_script_and_what_it_requires():
    classes, _ = execclass.classify({
        "package.json": _pkg(scripts={"postinstall": "node scripts/setup.js"}),
        "scripts/setup.js": b"require('./helper');\n",
        "scripts/helper.js": b"module.exports = 1;\n",
    })
    assert classes["scripts/setup.js"][0] == "install" and "postinstall" in classes["scripts/setup.js"][1]
    assert classes["scripts/helper.js"][0] == "install"


def test_shell_script_named_by_an_install_hook():
    classes, _ = execclass.classify({"package.json": _pkg(scripts={"preinstall": "sh ./setup.sh"}),
                                     "setup.sh": b"echo hi\n"})
    assert classes["setup.sh"][0] == "install"


def test_main_default_exports_and_bin():
    classes, _ = execclass.classify({
        "package.json": _pkg(exports={".": {"require": "./lib/a.js"}}, bin={"tool": "bin/tool"}),
        "index.js": b"",
        "lib/a.js": b"import x from './b.js';\n",
        "lib/b.js": b"",
        "bin/tool": b"#!/usr/bin/env node\n",
        "lib/unused.js": b"",
    })
    assert classes["lib/a.js"][0] == "load" and classes["lib/b.js"][0] == "load"
    assert classes["bin/tool"][0] == "command"
    assert classes["lib/unused.js"][0] == "other"
    assert classes["index.js"][0] == "other"          # "main" absent but exports present: exports wins


def test_index_js_is_main_by_default():
    classes, _ = execclass.classify({"package.json": _pkg(), "index.js": b""})
    assert classes["index.js"][0] == "load"


def test_not_shipped_inert_and_data():
    classes, _ = execclass.classify({
        "package.json": _pkg(),
        "test/a.test.js": b"",
        "README.md": b"# hi",
        "dist/app.js.map": b"{}",
        "config/data.json": b"{}",
    })
    assert classes["test/a.test.js"][0] == "not-shipped"
    assert classes["README.md"][0] == "inert" and classes["dist/app.js.map"][0] == "inert"
    assert classes["config/data.json"][0] == "data"


def test_loaders_of_a_data_file():
    classes, loaders = execclass.classify({
        "package.json": _pkg(main="index.js"),
        "index.js": b"const d = require('./config/data.json');\nconsole.log(d);\n",
        "config/data.json": b"{}",
    })
    assert classes["config/data.json"][0] == "data"
    assert loaders["config/data.json"] == ["index.js:1: const d = require('./config/data.json');"]


def test_an_inert_looking_file_that_shipped_code_reads_is_data():
    classes, loaders = execclass.classify({
        "package.json": _pkg(main="index.js"),
        "index.js": b"const t = require('fs').readFileSync(__dirname + '/notes/payload.md', 'utf8');\n",
        "notes/payload.md": b"x",
    })
    assert classes["notes/payload.md"] == ("data", "read by index.js")
    assert loaders["notes/payload.md"]


def test_odd_input_never_raises():
    classes, loaders = execclass.classify({"package.json": b"{not json", "a.js": b"\xff\xfe require('"})
    assert set(classes) == {"package.json", "a.js"} and loaders == {}


def test_a_code_file_is_never_inert_by_its_name():
    classes, _ = execclass.classify({"package.json": _pkg(), "lib/notice.js": b"x()", "history.js": b"x()",
                                     "setup.md": b"#!/usr/bin/env node\nx()\n"})
    assert all(classes[p][0] == "other" for p in ("lib/notice.js", "history.js", "setup.md"))
