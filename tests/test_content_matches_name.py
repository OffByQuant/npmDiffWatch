import io
import tarfile

from npmdiffwatch import content, sandbox
from npmdiffwatch.config import Config
from npmdiffwatch.models import Download


def test_documentation_that_is_documentation():
    assert content.matches_name("README.md", "# Title\n\nSome words.\n\n```js\nconst x = require('y');\n```\n")
    assert content.matches_name("dist/a.js.map", '{"version": 3, "mappings": "AAAA"}')
    assert content.matches_name("lib/a.d.ts", "export declare function f(x: string): void;\n")
    assert content.matches_name("style.css", "a { color: red; }\n.b { margin: 0; }\n")
    assert content.matches_name("icon.svg", "<svg xmlns='http://www.w3.org/2000/svg'></svg>")
    assert content.matches_name("LICENSE", "MIT License\n\nPermission is hereby granted...\n")


def test_code_wearing_a_documentation_name():
    js = "const https = require('https');\nconst d = process.env;\nmodule.exports = () => eval(d.X);\n"
    assert not content.matches_name("notes/README.md", js)
    assert not content.matches_name("dist/a.js.map", js)
    assert not content.matches_name("lib/a.d.ts", "require('child_process').exec('x');\n")
    assert not content.matches_name("page.html", js)
    assert not content.matches_name("style.css", js)


def test_empty_text_matches():
    assert content.matches_name("README.md", "")


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, b in files.items():
            ti = tarfile.TarInfo(f"package/{n}"); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def test_the_parent_relabels_a_mismatched_doc_as_data():
    pj0, pj1 = b'{"name":"p","version":"1.0.0"}', b'{"name":"p","version":"1.0.1"}'
    js = b"const h = require('https');\nmodule.exports = () => eval(process.env.X);\n"
    dl = Download("p", "1.0.1", "1.0.0", False,
                  _tgz({"package.json": pj1, "index.js": b"1", "docs.md": js, "README.md": b"# hi\n"}),
                  _tgz({"package.json": pj0, "index.js": b"1", "README.md": b"# old\n"}),
                  maintainer_metadata={})
    _, d, _ = sandbox.analyze(Config(), dl, None, backend="off")
    assert d.file_classes["docs.md"][0] == "data"
    assert d.file_classes["README.md"][0] == "inert"
    assert {"docs.md", "README.md"} <= {f.path for f in d.changed}
