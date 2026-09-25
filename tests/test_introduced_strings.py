from npmdiffwatch import strings
from npmdiffwatch.models import Diff, FileDiff, Hunk


def _diff(lines, path="a.js"):
    return Diff("p", "1", False, [FileDiff(path, "modified", [Hunk((0, 0), (3, 3 + len(lines)), lines, [])])], [])


def test_urls_ips_secret_paths_and_credential_env():
    got = strings.introduced(_diff([
        "fetch('https://api.example.invalid/v1')",
        "const h = '192.0.2.10';",
        "read(os.homedir() + '/.npmrc'); read('~/.aws/credentials')",
        "const t = process.env.NPM_TOKEN || process.env.HOME;",
    ]))
    assert ("url", "https://api.example.invalid/v1", "a.js:4") in got
    assert ("ip", "192.0.2.10", "a.js:5") in got
    assert ("secret-path", "/.npmrc", "a.js:6") in got and ("secret-path", "~/.aws/credentials", "a.js:6") in got
    assert ("credential-env", "NPM_TOKEN", "a.js:7") in got
    assert not any(v == "HOME" for _, v, _ in got)


def test_removed_lines_and_duplicates_are_ignored():
    d = Diff("p", "1", False, [FileDiff("a.js", "modified",
                                        [Hunk((0, 1), (0, 2), ["x('https://a.example.invalid')",
                                                               "y('https://a.example.invalid')"],
                                              ["z('https://gone.example.invalid')"])])], [])
    got = strings.introduced(d)
    assert got == [("url", "https://a.example.invalid", "a.js:1")]


def test_limit():
    assert len(strings.introduced(_diff([f"'https://h{i}.example.invalid'" for i in range(100)]), limit=40)) == 40
