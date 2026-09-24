import difflib
import json

from .models import ArtifactSet, Diff, FileDiff, Hunk, PkgJsonChange


def _lines(b: bytes) -> list[str]:
    return b.decode("utf-8", errors="replace").splitlines()


_JSON_FIELDS = {"name", "version", "description", "main", "bin", "scripts",
                "dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundledDependencies", "files",
                "type", "exports", "imports", "engines"}


def _diff_json(old_bytes: bytes | None, new_bytes: bytes | None) -> tuple[list[PkgJsonChange], frozenset]:
    old = json.loads(old_bytes.decode("utf-8", errors="replace")) if old_bytes else {}
    new_json = json.loads(new_bytes.decode("utf-8", errors="replace")) if new_bytes else {}
    changes = []
    old_scripts = old.get("scripts", {}) or {}
    new_scripts = new_json.get("scripts", {}) or {}
    changed_scripts = set()
    for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
        old_val = old_scripts.get(hook)
        new_val = new_scripts.get(hook)
        if old_val != new_val and new_val is not None:
            changed_scripts.add(hook)
    for field in _JSON_FIELDS:
        ov = old.get(field)
        nv = new_json.get(field)
        if ov != nv:
            changes.append(PkgJsonChange(field, json.dumps(ov) if ov is not None else None,
                                         json.dumps(nv) if nv is not None else None))
    return changes, frozenset(changed_scripts)


def _diff_lockfile(old_bytes: bytes | None, new_bytes: bytes | None) -> tuple[bool, bool]:
    has_new = False
    has_integrity = False
    old_pkgs: dict = {}
    new_pkgs: dict = {}
    if old_bytes:
        try:
            old_json = json.loads(old_bytes.decode("utf-8", errors="replace"))
            old_pkgs = old_json.get("packages", {})
        except (json.JSONDecodeError, ValueError):
            pass
    if new_bytes:
        try:
            new_json = json.loads(new_bytes.decode("utf-8", errors="replace"))
            new_pkgs = new_json.get("packages", {})
        except (json.JSONDecodeError, ValueError):
            pass
    for pkg in new_pkgs:
        if pkg not in old_pkgs:
            has_new = True
        else:
            old_int = old_pkgs[pkg].get("integrity")
            new_int = new_pkgs[pkg].get("integrity")
            if old_int and new_int and old_int != new_int:
                has_integrity = True
    return has_new, has_integrity


def _description(new_files) -> str:
    try:
        d = json.loads(new_files.get("package.json") or b"{}").get("description")
    except (ValueError, AttributeError):
        return ""
    return " ".join(d.split())[:500] if isinstance(d, str) else ""     # one line: it must not pose as a hunk


def build_diff(a: ArtifactSet) -> Diff:
    changed: list[FileDiff] = []
    pkg_changes: list[PkgJsonChange] = []
    changed_scripts_set: frozenset = frozenset()
    lock_meta: dict[str, bool] = {}

    for path in sorted(set(a.new_files) | set(a.prior_files)):
        new, prior = a.new_files.get(path), a.prior_files.get(path)
        if new is not None and prior is not None and new == prior:
            continue
        nl, pl = _lines(new or b""), _lines(prior or b"")

        if path == "package.json":
            pkg_changes, cs = _diff_json(prior, new)
            if cs:
                changed_scripts_set = cs
            if pkg_changes and (new is not None or prior is not None):
                hunks = _build_hunks(nl, pl)
                new_text = new.decode("utf-8", errors="replace") if new is not None else None
                changed.append(FileDiff(path, "added" if prior is None else "removed" if new is None else "modified",
                                        hunks, new_text))
                continue

        if path in ("package-lock.json", "npm-shrinkwrap.json"):
            hn, hi = _diff_lockfile(prior, new)
            lock_meta = {"has_new_packages": hn, "has_integrity_changes": hi}
            if new is not None or prior is not None:
                hunks = _build_hunks(nl, pl)
                new_text = new.decode("utf-8", errors="replace") if new is not None else None
                changed.append(FileDiff(path, "added" if prior is None else "removed" if new is None else "modified",
                                        hunks, new_text))
                continue

        kind = "added" if prior is None else "removed" if new is None else "modified"
        hunks = _build_hunks(nl, pl)
        if hunks:
            new_text = new.decode("utf-8", errors="replace") if new is not None else None
            changed.append(FileDiff(path, kind, hunks, new_text))

    diff = Diff(a.package, a.version, a.prior_version is None, changed,
                list(a.added_binaries), list(a.added_dep_findings), pkg_changes, _description(a.new_files))
    # Side-channel metadata read back via getattr() in facts.build_facts; Diff is
    # frozen, so set through object.__setattr__ rather than plain assignment.
    object.__setattr__(diff, "_lock_meta", lock_meta)
    object.__setattr__(diff, "_changed_scripts", changed_scripts_set)
    return diff


def _build_hunks(nl: list[str], pl: list[str]) -> list[Hunk]:
    hunks: list[Hunk] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, pl, nl).get_opcodes():
        if tag == "equal":
            continue
        hunks.append(Hunk((i1, i2), (j1, j2), nl[j1:j2], pl[i1:i2]))
    return hunks
