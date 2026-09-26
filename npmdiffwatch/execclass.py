"""When each file in a release runs, from its package.json and the files' own literal imports. Facts only: a
class tells the reviewer where to look first; it never clears or convicts anything."""
import json
import posixpath
import re

from .content import DOC_EXT as _DOC_EXT, DOC_NAMES as _DOC_NAMES

CLASSES = ("install", "load", "command", "other", "data", "not-shipped", "inert")

_CODE_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")
_TYPES_EXT = (".d.ts", ".d.mts", ".d.cts")
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py")
_INERT_EXT = _DOC_EXT
_INERT_NAMES = _DOC_NAMES
_NOT_SHIPPED = {"test", "tests", "__tests__", "spec", "specs", "example", "examples", "doc", "docs",
                "benchmark", "benchmarks", "fixtures", "__mocks__"}
_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
_RESOLVE_EXT = ("", ".js", ".cjs", ".mjs", ".json", ".ts", "/index.js")
_DEPTH = 3
_MAX_LOADER_LINES = 5
_IMPORT = re.compile(r"""(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]|\bfrom\s+['"]([^'"\n]+)['"]"""
                     r"""|^\s*import\s+['"]([^'"\n]+)['"]""", re.M)
_LITERAL = re.compile(r"""['"`]([^'"`\s]{1,200})['"`]""")


def _text(b) -> str:
    return b.decode("utf-8", errors="replace") if isinstance(b, bytes) else ""


def _manifest(files) -> dict:
    try:
        pj = json.loads(files.get("package.json") or b"{}")
    except (ValueError, UnicodeDecodeError, RecursionError):
        return {}
    return pj if isinstance(pj, dict) else {}


def _norm(p: str) -> str | None:
    p = posixpath.normpath(p.strip())
    return None if p.startswith("..") or p.startswith("/") or p == "." else p


def _resolve(path: str, files) -> str | None:
    base = _norm(path)
    if base is None:
        return None
    for ext in _RESOLVE_EXT:
        if base + ext in files:
            return base + ext
    return None


def _is_code(path: str, files) -> bool:
    low = path.lower()
    if low.endswith(_TYPES_EXT):
        return False
    return low.endswith(_CODE_EXT + _SCRIPT_EXT) or _text(files.get(path, b""))[:2] == "#!"


def _imports(path: str, files) -> list[str]:
    out = []
    for m in _IMPORT.finditer(_text(files.get(path))):
        spec = next(g for g in m.groups() if g)
        if spec.startswith("."):
            r = _resolve(posixpath.join(posixpath.dirname(path), spec), files)
            if r and _is_code(r, files):     # a required JSON file is data: it has loaders, it does not run
                out.append(r)
    return out


def _closure(roots, files) -> list[str]:
    seen, frontier = list(dict.fromkeys(roots)), list(dict.fromkeys(roots))
    for _ in range(_DEPTH):
        nxt = []
        for p in frontier:
            for q in _imports(p, files):
                if q not in seen:
                    seen.append(q); nxt.append(q)
        frontier = nxt
    return seen


def _command_files(cmd, files) -> list[str]:
    if not isinstance(cmd, str):
        return []
    out = []
    for tok in re.split(r"[\s;&|()<>]+", cmd):
        r = _resolve(tok, files) if tok and not tok.startswith("-") else None
        if r and r not in out:
            out.append(r)
    return out


def _export_targets(value) -> list[str]:
    if isinstance(value, str):
        return [value] if value.startswith("./") else []
    if isinstance(value, dict):
        return [t for v in value.values() for t in _export_targets(v)]
    if isinstance(value, list):
        return [t for v in value for t in _export_targets(v)]
    return []


def _roots(pj, files):
    """(class, why, root files) in review order."""
    scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
    for hook in _INSTALL_HOOKS:
        yield "install", f"the {hook} script runs it", _command_files(scripts.get(hook), files)
    load = [r for t in _export_targets(pj.get("exports")) if (r := _resolve(t, files))]
    if isinstance(pj.get("main"), str):
        load += [r for r in [_resolve(pj["main"], files)] if r]
    elif not pj.get("exports") and "index.js" in files:
        load.append("index.js")          # npm's default entry point
    yield "load", "loaded when a program imports the package", load
    bin_ = pj.get("bin")
    if isinstance(bin_, str):
        bin_ = {"": bin_}
    cmd = [r for v in (bin_.values() if isinstance(bin_, dict) else []) if (r := _resolve(str(v), files))]
    yield "command", "runs when the user types its command (bin)", cmd


def hook_files(files: dict, hooks) -> dict[str, str]:
    """Files the given install hooks run directly, with the hook that runs each."""
    scripts = _manifest(files).get("scripts")
    scripts = scripts if isinstance(scripts, dict) else {}
    out: dict[str, str] = {}
    for hook in _INSTALL_HOOKS:
        if hook in hooks:
            for p in _command_files(scripts.get(hook), files):
                out.setdefault(p, hook)
    return out


def _loaders(files, shipped, targets) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for f in shipped:
        for i, line in enumerate(_text(files.get(f)).splitlines(), 1):
            for lit in _LITERAL.findall(line):
                for cand in (_norm(posixpath.join(posixpath.dirname(f), lit)), _norm(lit.lstrip("/"))):
                    if cand in targets and len(found.setdefault(cand, [])) < _MAX_LOADER_LINES:
                        entry = f"{f}:{i}: {line.strip()[:200]}"
                        if entry not in found[cand]:
                            found[cand].append(entry)
    return found


def classify(files: dict) -> tuple[dict[str, tuple[str, str]], dict[str, list[str]]]:
    pj = _manifest(files)
    classes: dict[str, tuple[str, str]] = {}
    for cls, why, roots in _roots(pj, files):
        for p in _closure(roots, files):
            if p in roots:
                reason = why
            elif cls == "install":
                reason = "required by a file an install script runs"
            else:
                reason = f"required by an entry file ({cls})"
            classes.setdefault(p, (cls, reason))
    for p in files:
        if p in classes:
            continue
        segs = p.lower().split("/")
        base = segs[-1]
        if _NOT_SHIPPED & set(segs[:-1]) or ".test." in base or ".spec." in base:
            classes[p] = ("not-shipped", "test, example or docs path")
        elif _is_code(p, files):         # before the name test: a name never makes code inert
            classes[p] = ("other", "shipped code; no entry point names it")
        elif base.endswith(_INERT_EXT) or base.split(".")[0] in _INERT_NAMES:
            classes[p] = ("inert", "documentation, styles, source map or type declarations")
        else:
            classes[p] = ("data", "data file shipped with the package")
    shipped = [p for p, (c, _) in classes.items() if c in ("install", "load", "command", "other")]
    targets = {p for p, (c, _) in classes.items() if c in ("data", "inert")}
    loaders = _loaders(files, shipped, targets)
    for p, lines in loaders.items():
        if classes[p][0] == "inert":
            classes[p] = ("data", f"read by {lines[0].split(':', 1)[0]}")
    return classes, loaders
