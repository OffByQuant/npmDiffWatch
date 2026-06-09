"""The dashboard file server must bind localhost by default (the safe default for a
security tool's UI) but allow an explicit host so it can be exposed to the LAN on demand."""
from npmdiffwatch.__main__ import _file_server


def test_file_server_defaults_to_localhost(tmp_path):
    httpd = _file_server(tmp_path, 0)
    try:
        assert httpd.server_address[0] == "127.0.0.1"
    finally:
        httpd.server_close()


def test_file_server_binds_explicit_host(tmp_path):
    httpd = _file_server(tmp_path, 0, host="0.0.0.0")
    try:
        assert httpd.server_address[0] == "0.0.0.0"
    finally:
        httpd.server_close()
