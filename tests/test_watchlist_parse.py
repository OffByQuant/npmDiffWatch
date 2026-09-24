# tests/test_watchlist_parse.py
"""Watchlist files are parsed as data only. Four formats, detected from content."""
import json

import pytest

from npmdiffwatch import watchlist


def _w(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text if isinstance(text, str) else json.dumps(text))
    return watchlist.load(p)


def test_names_file_exact_scoped_patterns_comments_and_invalid(tmp_path):
    w = _w(tmp_path, "deps.txt", "# ours\nleft-pad\n@babel/core\n\n@gooddata/*\nreact-*\nnot a name!\nJSONStream\n")
    assert w.fmt == "names" and w.names == {"left-pad", "@babel/core", "JSONStream"}
    assert w.patterns == ("@gooddata/*", "react-*") and w.skipped == 1
    assert w.matches("@gooddata/sdk-backend-tiger") and w.matches("react-dom") and w.matches("left-pad")
    assert not w.matches("lodash") and not w.matches("@babel/cli")


def test_lockfile_v3_nested_scoped_skips_root_and_links(tmp_path):
    w = _w(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/a": {}, "node_modules/@s/b": {},
        "node_modules/a/node_modules/c": {}, "node_modules/local-ws": {"link": True}, "packages/ws": {}}})
    assert w.fmt == "package-lock" and w.names == {"a", "@s/b", "c"}


def test_lockfile_v1_recursive_dependencies(tmp_path):
    w = _w(tmp_path, "package-lock.json", {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}, "@s/c": {"version": "3.0.0"}}})
    assert w.names == {"a", "b", "@s/c"}


def test_cyclonedx_nested_components_and_encoded_purls(tmp_path):
    w = _w(tmp_path, "bom.json", {"bomFormat": "CycloneDX", "components": [
        {"purl": "pkg:npm/%40babel/core@7.0.0?foo=bar#sub"},
        {"purl": "pkg:npm/left-pad@1.3.0", "components": [{"purl": "pkg:npm/inner@1.0.0"}]},
        {"purl": "pkg:pypi/requests@2.0.0"}, {"name": "no-purl"}]})
    assert w.fmt == "cyclonedx" and w.names == {"@babel/core", "left-pad", "inner"}


def test_spdx_purl_external_refs(tmp_path):
    w = _w(tmp_path, "sbom.spdx.json", {"spdxVersion": "SPDX-2.3", "packages": [
        {"externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/%40s/x@1.0.0"}]},
        {"externalRefs": [{"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:x"}]}]})
    assert w.fmt == "spdx" and w.names == {"@s/x"}


@pytest.mark.parametrize("name,text,msg", [
    ("missing.txt", None, "cannot read"),
    ("empty.txt", "# nothing\n\n", "no packages"),
    ("other.json", {"hello": 1}, "not a recognized"),
    ("bad.json", "{not json", "not a recognized"),
])
def test_unusable_files_raise_with_the_path_and_formats(tmp_path, name, text, msg):
    p = tmp_path / name
    if text is not None:
        p.write_text(text if isinstance(text, str) else json.dumps(text))
    with pytest.raises(watchlist.WatchlistError) as e:
        watchlist.load(p)
    assert msg in str(e.value) and str(p) in str(e.value)


def test_describe(tmp_path):
    w = _w(tmp_path, "deps.txt", "a\nb\n@s/*\n")
    assert w.describe() == "deps.txt · 2 packages, 1 pattern"
