from dataclasses import replace
import hashlib
import io
import json
import shutil
import sys
import tarfile

import pytest

from npmdiffwatch import sandbox
from npmdiffwatch.config import Config


def test_exact_extraction_does_not_replace_invalid_utf8(monkeypatch):
    data = b"const x = '\xff';"
    def run(cfg, backend, payload):
        head = json.loads(payload.split(b"\n", 1)[0])
        assert head["exact_bytes"] and backend == "seatbelt"
        return json.dumps({"files_hex": {"index.js": data.hex()}, "binaries": []}).encode()
    monkeypatch.setattr(sandbox, "_run", run)
    files, bins = sandbox.extract_exact_files(Config(), b"unopened archive fixture", "seatbelt")
    assert files["index.js"] == data and bins == []


def test_exact_extraction_requires_sandbox():
    with pytest.raises(sandbox.SandboxError, match="working sandbox"):
        sandbox.extract_exact_files(Config(), b"blob", "off")


@pytest.mark.parametrize("out", [{"files_hex": {"../escape.js": "00"}, "binaries": []},
                                {"files_hex": {"index.js": "not hex"}, "binaries": []},
                                {"files_hex": {}, "binaries": [{"path": "../escape"}]},
                                {"error": "refused"}])
def test_invalid_exact_extraction_is_not_admitted(monkeypatch, out):
    monkeypatch.setattr(sandbox, "_run", lambda *args: json.dumps(out).encode())
    with pytest.raises(sandbox.SandboxError):
        sandbox.extract_exact_files(Config(), b"blob", "seatbelt")


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"), reason="requires Seatbelt")
def test_execution_context_keeps_instruction_assets_and_loaded_data_in_scope(tmp_path):
    instructions = ("SKILL.md", "AGENTS.md", "CLAUDE.md", "system.md", "prompt.md", "nested/AgEnTs.md")
    files = {"package.json": b'{"main":"index.js"}',
             "index.js": b"const fs=require('node:fs'); fs.readFileSync('LICENSE','utf8');",
             "LICENSE": b"Permission is granted to use this software.",
             "README.md": b"# Ordinary project documentation\n",
             "NOTES.md": b"const cp=require('node:child_process'); cp.execSync('example');",
             **{p: b"# Instructions\nFollow the project instructions.\n" for p in instructions}}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, data in files.items():
            member = tarfile.TarInfo("package/" + path)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    blob = buffer.getvalue()
    cfg = replace(Config(), db_path=tmp_path / "db.sqlite")
    exact, bins, context = sandbox.extract_exact_files(cfg, blob, "seatbelt", with_context=True)
    assert exact == files and not bins
    assert context["artifact_sha256"] == hashlib.sha256(blob).hexdigest()
    metadata = context["files"]
    assert metadata["README.md"]["verified_inert"]
    assert not any(metadata[p]["verified_inert"] for p in (*instructions, "NOTES.md", "LICENSE"))
    assert metadata["LICENSE"]["readers"] == ["index.js"]
    assert metadata["index.js"]["reads"] == ["LICENSE"]


@pytest.mark.parametrize("metadata", [None, [], {"index.js": None}, {"index.js": []}])
def test_malformed_execution_context_is_a_sandbox_error(monkeypatch, metadata):
    blob = b"fixture"
    out = {"files_hex": {"index.js": b"x".hex()}, "binaries": [], "execution_context": {
        "artifact_sha256": hashlib.sha256(blob).hexdigest(), "engine": "sandbox-static-inventory-2", "files": metadata}}
    monkeypatch.setattr(sandbox, "_run", lambda *args: json.dumps(out).encode())
    with pytest.raises(sandbox.SandboxError):
        sandbox.extract_exact_files(Config(), blob, "seatbelt", with_context=True)
