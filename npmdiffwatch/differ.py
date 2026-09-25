import difflib
import json

from . import execclass
from .models import ArtifactSet, Diff, FileDiff, Hunk, PkgJsonChange


def _lines(b: bytes) -> list[str]:
    return b.decode("utf-8", errors="replace").splitlines()


_JSON_FIELDS = {"name", "version", "description", "main", "bin", "scripts",
                "dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundledDependencies", "files",
                "type", "exports", "imports", "engines"}


def manifest_fields(version_data) -> dict | None:
    """The package.json fields the differ compares, from a registry version document (which also carries the
    readme, dist info and more)."""
    if not isinstance(version_data, dict):
        return None
    return {k: version_data[k] for k in _JSON_FIELDS if k in version_data}


def _json_object(raw: bytes | None) -> dict:
    """An author-written JSON file as a dict: {} when it is missing, broken or not an object. Parsing the bytes
    (not decoded text) accepts a UTF-8 byte-order mark. Never raises: a release that fails to process holds
    the cursor, so one bad file would stall the scan."""
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _diff_json(old_bytes: bytes | None, new_bytes: bytes | None) -> tuple[list[PkgJsonChange], frozenset, str]:
    old = _json_object(old_bytes)
    new_json = _json_object(new_bytes)
    changes = []
    old_scripts = _dict(old.get("scripts"))
    new_scripts = _dict(new_json.get("scripts"))
    changed_scripts = set()
    for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
        old_val = old_scripts.get(hook)
        new_val = new_scripts.get(hook)
        if old_val != new_val and new_val is not None:
            changed_scripts.add(hook)
    for field in sorted(_JSON_FIELDS):
        ov = old.get(field)
        nv = new_json.get(field)
        if ov != nv:
            changes.append(PkgJsonChange(field, json.dumps(ov) if ov is not None else None,
                                         json.dumps(nv) if nv is not None else None))
    # The text of the install-time scripts this version adds or changes, for the install_script_contains check.
    # Each ends in " ;" so a pattern like "| sh " also matches a pipe at the very end of a script.
    text = "".join(f"{new_scripts[h]} ; " for h in ("preinstall", "install", "postinstall") if h in changed_scripts)
    return changes, frozenset(changed_scripts), text


def _diff_lockfile(old_bytes: bytes | None, new_bytes: bytes | None) -> tuple[bool, bool]:
    has_new = False
    has_integrity = False
    old_pkgs = _dict(_json_object(old_bytes).get("packages"))
    new_pkgs = _dict(_json_object(new_bytes).get("packages"))
    for pkg in new_pkgs:
        if pkg not in old_pkgs:
            has_new = True
        else:
            old_int = _dict(old_pkgs[pkg]).get("integrity")
            new_int = _dict(new_pkgs[pkg]).get("integrity")
            if old_int and new_int and old_int != new_int:
                has_integrity = True
    return has_new, has_integrity


def _description(new_files) -> str:
    d = _json_object(new_files.get("package.json")).get("description")
    return " ".join(d.split())[:500] if isinstance(d, str) else ""     # one line: it must not pose as a hunk


def build_diff(a: ArtifactSet) -> Diff:
    changed: list[FileDiff] = []
    pkg_changes: list[PkgJsonChange] = []
    changed_scripts_set: frozenset = frozenset()
    changed_script_text = ""
    lock_meta: dict[str, bool] = {}
    classes, loaders = execclass.classify(a.new_files)
    file_classes: dict[str, list[str]] = {}
    listed: list[dict] = []

    for path in sorted(set(a.new_files) | set(a.prior_files)):
        new, prior = a.new_files.get(path), a.prior_files.get(path)
        if new is not None and prior is not None and new == prior:
            continue
        cls, why = classes.get(path, ("not-shipped", "removed in this version"))
        file_classes[path] = [cls, why]
        if cls == "inert":
            listed.append({"path": path, "size": len(new or b""), "class": "inert"})
            continue
        nl, pl = _lines(new or b""), _lines(prior or b"")

        if path == "package.json":
            pkg_changes, cs, changed_script_text = _diff_json(prior, new)
            if a.prior_version is None:
                # First release: every field is "new", so only an install-time script is a signal.
                pkg_changes = [c for c in pkg_changes if c.field == "scripts"] if cs else []
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
                list(a.added_binaries), list(a.added_dep_findings), pkg_changes, _description(a.new_files),
                {p: c for p, c in file_classes.items() if p in {f.path for f in changed} or c[0] == "inert"},
                {p: ls for p, ls in loaders.items() if p in {f.path for f in changed}}, listed,
                publishing=((a.maintainer_metadata or {}).get("publishing") or {}))
    # Side-channel metadata read back via getattr() in facts.build_facts; Diff is
    # frozen, so set through object.__setattr__ rather than plain assignment.
    object.__setattr__(diff, "_lock_meta", lock_meta)
    object.__setattr__(diff, "_changed_scripts", changed_scripts_set)
    object.__setattr__(diff, "_changed_script_text", changed_script_text)
    return diff


def _build_hunks(nl: list[str], pl: list[str]) -> list[Hunk]:
    hunks: list[Hunk] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, pl, nl).get_opcodes():
        if tag == "equal":
            continue
        hunks.append(Hunk((i1, i2), (j1, j2), nl[j1:j2], pl[i1:i2]))
    return hunks
