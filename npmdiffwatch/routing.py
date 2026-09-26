"""Which review a release gets. A release is cleared without the model only when nothing that can run changed;
everything else goes to the model. Rules never clear and never escalate: they only order the queue."""
import json
import re
from dataclasses import dataclass

from . import content

_RUNNABLE = {"install": 3, "load": 2, "command": 1, "other": 1, "data": 1}
_MANIFESTS = {"package.json", "package-lock.json"}
_PKG_FREE = {"version", "devDependencies"}
_DEP_FIELDS = {"dependencies", "peerDependencies", "optionalDependencies"}


@dataclass(frozen=True)
class Route:
    tier: str                  # "fact": cleared, nothing runnable changed; "model": the model reviews it
    why: tuple[str, ...]       # what kept it from being cleared by fact
    priority: int              # queue order when the model is behind: 3 install, 2 load, 1 other signals, 0


_RANGE = re.compile(r"[\w.\-+*^~<>=| ]*")     # a semver range or dist-tag: no ':' or '/', so no URL, alias or path
_HOOKS = ("preinstall", "install", "postinstall")


def _json(v):
    try:
        return json.loads(v or "{}")
    except ValueError:
        return None


def _only_bumps(c) -> bool:
    """Existing registry dependencies moved to another version range, or dropped. A spec that fetches code from
    anywhere else (a URL, git, an npm: alias, a path, a GitHub shorthand) is not a bump."""
    old, new = _json(c.old), _json(c.new)
    return (isinstance(old, dict) and isinstance(new, dict) and set(new) <= set(old)
            and all(isinstance(v, str) and _RANGE.fullmatch(v) for k, v in new.items() if old[k] != v))


def _install_hooks_changed(c) -> bool:
    old, new = _json(c.old), _json(c.new)
    old, new = old if isinstance(old, dict) else {}, new if isinstance(new, dict) else {}
    return any(old.get(h) != new.get(h) for h in _HOOKS)


def route(diff, registry_changes=()) -> Route:
    """registry_changes: package.json changes from the registry's own manifest, which the parent holds; they
    count even when the tarball's package.json shows none."""
    why: list[str] = []
    prio = 0
    if diff.is_first_release:
        why.append("first release")
    for fd in diff.changed:
        if fd.path in _MANIFESTS or fd.change_kind == "removed":
            continue
        cls = (diff.file_classes.get(fd.path) or ["other"])[0]
        if cls in _RUNNABLE:
            why.append(f"{cls} file changed")
            prio = max(prio, _RUNNABLE[cls])
        elif cls == "not-shipped" and not (content.looks_like_doc(fd.path)
                                            and content.matches_name(fd.path, fd.new_text or "")):
            why.append("code under a test or example path changed")
        elif cls == "inert" and not (content.looks_like_doc(fd.path)
                                      and content.matches_name(fd.path, fd.new_text or "")):
            why.append("a documentation-named file does not contain documentation")
            prio = max(prio, 1)
    for c in list(diff.package_json_changes) + list(registry_changes):
        if c.field in _PKG_FREE or (c.field in _DEP_FIELDS and _only_bumps(c)):
            continue
        why.append(f"package.json {c.field} changed")
        prio = max(prio, 3 if c.field == "scripts" and _install_hooks_changed(c)
                   else 2 if c.field in ("main", "exports", "bin") else 1)
    if any(fd.path == "npm-shrinkwrap.json" for fd in diff.changed):
        why.append("npm-shrinkwrap.json changed")
        prio = max(prio, 1)
    if diff.added_binaries:
        why.append("binary or foreign-language file added")
        prio = max(prio, 1)
    if diff.added_dep_findings:
        why.append("dependency screening lead")
        prio = max(prio, 1)
    p = diff.publishing or {}
    if not p:
        why.append("no publishing facts")
    else:
        dropped = [k for k, a, b in (("provenance", "provenance_before", "provenance_now"),
                                     ("trusted publisher", "trusted_publisher_before", "trusted_publisher_now"))
                   if p.get(a) and not p.get(b)]
        if p.get("publisher_changed") or p.get("maintainers_changed") or dropped:
            why.append("publishing changed")
            prio = max(prio, 1)
    return Route("model" if why else "fact", tuple(why), prio)
