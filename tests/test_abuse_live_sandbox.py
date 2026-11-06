from dataclasses import replace
import io
import shutil
import sys
import tarfile
import threading
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from npmdiffwatch import abuse_coordinator, sandbox, store
from npmdiffwatch.__main__ import _file_server
from npmdiffwatch.models import Download, NewRelease
from tests.test_abuse_live import Backend, config


def archive(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, data in files.items():
            entry = tarfile.TarInfo("package/" + path)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"), reason="requires Seatbelt")
def test_real_sandbox_queue_worker_keeps_original_bytes_and_never_executes_package(monkeypatch, tmp_path):
    cfg = replace(config(tmp_path), parse_rss_max_bytes=4 * 1024**3)
    monkeypatch.setattr(sandbox, "choose", lambda cfg: "seatbelt")
    current = {"package.json": b'{"name":"fixture","version":"2","main":"index.js"}',
        "index.js": b"export const value = 2;\r\n"}
    prior = {"package.json": b'{"name":"fixture","version":"1","main":"index.js"}',
        "index.js": b"export const value = 1;\r\n"}
    dl = Download("fixture", "2", "1", False, archive(current), archive(prior))
    conn = store.connect(cfg); store.init_schema(conn)
    abuse_coordinator.accept_fetch(cfg, conn, NewRelease("fixture", "2", 1), dl)
    conn.close()
    assert abuse_coordinator.drain(cfg, backend_factory=Backend) == 1
    conn = store.connect(cfg)
    result = store.all_verdicts(conn)[0]["abuse_result"]
    assert result["status"] == "no_abuse_found"
    for citation in result["candidate"]["citations"]:
        source = current if citation["span"]["artifact_sha256"] == result["artifacts"][0] else prior
        span = citation["span"]
        assert bytes.fromhex(citation["quote_hex"]) == source[span["path"]][span["start"]:span["end"]]
    assert not list(tmp_path.glob("**/index.js"))
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    conn.close()


def test_dashboard_server_never_serves_database_archives_or_directory_listing(tmp_path):
    (tmp_path / "dashboard.html").write_text("<!doctype html><title>safe dashboard</title>")
    (tmp_path / "d.sqlite").write_bytes(b"private evidence")
    (tmp_path / "archive.tgz").write_bytes(b"unopened package")
    server = _file_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(base + "/") as response:
            assert b"safe dashboard" in response.read()
            assert response.headers["X-Content-Type-Options"] == "nosniff"
        for path in ("/d.sqlite", "/archive.tgz", "/%64.sqlite", "/../d.sqlite", "/%2e%2e/d.sqlite"):
            with pytest.raises(HTTPError) as error:
                urlopen(base + path)
            assert error.value.code == 404
    finally:
        server.shutdown(); thread.join(); server.server_close()
