"""One file too big for the input does not hide the smaller runnable files after it."""
from npmdiffwatch import reviewer
from npmdiffwatch.models import Diff, FileDiff, Hunk, TriageResult


def _fd(path, n):
    return FileDiff(path, "modified", [Hunk((1, 1), (1, 1), ["x" * n], [])], None)


def test_a_file_that_does_not_fit_is_skipped_not_the_rest():
    d = Diff("p", "1.0.1", False, [_fd("dist/big.js", 50_000), _fd("lib/send.js", 200)], [], [], [], "",
             {"dist/big.js": ["load", "main"], "lib/send.js": ["load", "required by an entry file (load)"]},
             {}, [], {})
    text = reviewer.build_review_input(d, TriageResult(0.0, [], False), max_chars=10_000)
    assert "--- file: lib/send.js (modified) ---" in text
    assert "--- file: dist/big.js" not in text and "dist/big.js (load," in text.split("not shown")[-1]
