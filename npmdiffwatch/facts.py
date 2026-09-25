import math
import posixpath
import re
from dataclasses import dataclass

_PRIM_EXEC = {"eval", "Function", "setTimeout", "setInterval"}
_PRIM_PROCESS = {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
_PRIM_NETWORK = {"fetch", "request"}
_PRIM_DECODE = {"from", "atob", "btoa", "fromCharCode"}
_PRIM_CREDENTIAL = {"env"}
_PRIM_FILE = {"writeFileSync", "writeFile", "appendFile", "chmod", "copyFile", "unlinkSync", "rmSync"}
_PRIM_PROTO = {"__proto__", "defineProperty"}
_PRIM_DYNAMIC_REQUIRE = {"require", "import"}

_PRIM_ALL = {
    "exec": _PRIM_EXEC, "process": _PRIM_PROCESS, "network": _PRIM_NETWORK,
    "decode": _PRIM_DECODE, "credential": _PRIM_CREDENTIAL,
    "file": _PRIM_FILE, "proto": _PRIM_PROTO, "dynamic_require": _PRIM_DYNAMIC_REQUIRE,
}

ENTROPY_X, ENTROPY_WINDOW, LONG_RUN_L, LONG_LINE = 4.5, 64, 128, 500
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{%d,}" % LONG_RUN_L)

_AUTOEXEC_PATHS = frozenset({
    "package.json", "preinstall.js", "install.js", "postinstall.js",
    "prepare.js", "prepublish.js", ".npmrc",
})

_SRC_EXT = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})


def _is_js(path: str) -> bool:
    return any(path.endswith(e) for e in _SRC_EXT)


def classify_location(path: str) -> float:
    base = posixpath.basename(path)
    if base in _AUTOEXEC_PATHS:
        return 3.0
    if base in {"index.js", "main.js", "cli.js"} or path.startswith("bin/") or "/bin/" in path:
        return 2.0          # runs whenever the package is loaded or its command is used, but not at install time
    segs = path.split("/")
    if any(s in {"tests", "test", "docs", "doc", "examples", "example"} for s in segs):
        return 0.2
    return 1.0


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _blob_present(added_strs) -> bool:
    for line in added_strs:
        if _B64_RUN.search(line) or len(line) > LONG_LINE:
            return True
        if len(line) >= ENTROPY_WINDOW and _entropy(line[:ENTROPY_WINDOW]) > ENTROPY_X:
            return True
    return False


def _walk_tree(node):
    yield node
    for child in node.children:
        yield from _walk_tree(child)


def _node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node.text else ""


def _node_field(node, name):
    if hasattr(node, "child_by_field_name"):
        return node.child_by_field_name(name)
    return None


_JS_PARSER = None


def _get_parser():
    global _JS_PARSER
    if _JS_PARSER is not None:
        return _JS_PARSER
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript as tsjavascript
        lang = Language(tsjavascript.language())
        _JS_PARSER = Parser(lang)
    except ImportError:
        _JS_PARSER = False
    return _JS_PARSER


def _parse_js(source: str):
    parser = _get_parser()
    if parser is False:
        return None
    try:
        return parser.parse(bytes(source, "utf-8"))
    except Exception:
        return None


def _call_func(node):
    func = _node_field(node, "function")
    if func is None and node.children:
        func = node.children[0]
    return func


def _member_parts(node):
    obj = _node_field(node, "object")
    prop = _node_field(node, "property")
    if obj is None and len(node.children) >= 3:
        obj = node.children[0]
    if prop is None and node.children:
        prop = node.children[-1]
    return obj, prop


def _resolve_call_name(node):
    func = _call_func(node)
    if func is None:
        return None, None
    if func.type == "identifier":
        return _node_text(func), None
    if func.type == "member_expression":
        obj, prop = _member_parts(func)
        if obj and prop:
            return _node_text(prop), _node_text(obj)
    return None, None


def _has_non_literal_arg(node):
    args = _node_field(node, "arguments")
    if args is None:
        for child in node.children:
            if child.type == "arguments":
                args = child
                break
    if args is None:
        return False
    # named_children skips punctuation ("(", ")", ","); a string/template arg is
    # a static module/path, anything else (identifier, concatenation, call) is dynamic.
    for child in args.named_children:
        if child.type not in ("string", "template_string"):
            return True
    return False


# A timer's first argument is evaluated as code only when it is a string; a function or a reference is a callback.
_CALLBACK_TYPES = {"arrow_function", "function_expression", "function", "identifier", "member_expression"}


def _timer_takes_code(node) -> bool:
    args = _node_field(node, "arguments")
    first = next((c for c in args.children if c.is_named), None) if args is not None else None
    return first is not None and first.type not in _CALLBACK_TYPES


def _find_categories(tree, added_lines):
    cats = set()
    names = set()
    if tree is None:
        return cats, names
    uses_child_process = "child_process" in _node_text(tree.root_node)
    for node in _walk_tree(tree.root_node):
        if node.type not in ("call_expression", "member_expression"):
            continue
        lo = (node.start_point[0] + 1) if node.start_point else 1
        hi = (node.end_point[0] + 1) if node.end_point else lo
        if added_lines.isdisjoint(range(lo, hi + 1)):
            continue
        if node.type == "member_expression":
            # credential read: process.env (with or without a trailing .KEY).
            obj, prop = _member_parts(node)
            if obj is not None and prop is not None \
                    and _node_text(obj) == "process" and _node_text(prop) == "env":
                cats.add("credential")
                names.add("process.env")
            continue
        name, obj = _resolve_call_name(node)
        if name is None:
            continue
        if name in {"setTimeout", "setInterval"} and not _timer_takes_code(node):
            continue
        if name == "exec" and not uses_child_process:
            continue        # RegExp#exec; a shell exec needs child_process in the file
        if name in _PRIM_EXEC:
            cats.add("exec")
            names.add(name)
            continue
        if name in _PRIM_PROCESS:
            cats.add("process")
            names.add(name)
            continue
        if name in _PRIM_NETWORK:
            cats.add("network")
            names.add(name)
            continue
        if name in _PRIM_DECODE and obj in ("Buffer", "String"):
            cats.add("decode")
            names.add(f"{obj}.{name}")
            continue
        if obj is not None:
            if obj == "process" and name == "env":
                cats.add("credential")
                names.add("process.env")
                continue
            if obj == "fs" and name in _PRIM_FILE:
                cats.add("file")
                names.add(f"fs.{name}")
                continue
            if obj == "child_process" and name in _PRIM_PROCESS:
                cats.add("process")
                names.add(f"child_process.{name}")
                continue
        # require() is a bare identifier call (obj is None); a non-literal target
        # is a dynamic require regardless of receiver.
        if name == "require" and _has_non_literal_arg(node):
            cats.add("dynamic_require")
            names.add("require")
            continue
    return cats, names


def _find_dynamic_imports(tree, added_lines):
    cats = set()
    if tree is None:
        return cats
    for node in _walk_tree(tree.root_node):
        if node.type == "import_statement" or node.type == "call_expression":
            lo = (node.start_point[0] + 1) if node.start_point else 1
            hi = (node.end_point[0] + 1) if node.end_point else lo
            if added_lines.isdisjoint(range(lo, hi + 1)):
                continue
            if node.type == "import_statement":
                source = _node_field(node, "source")
                if source and source.type not in ("string", "template_string"):
                    cats.add("dynamic_require")
            elif node.type == "call_expression":
                # Dynamic import(): the call's function node is an `import` keyword
                # node, so _resolve_call_name can't name it.
                func = _call_func(node)
                is_dyn_import = func is not None and func.type == "import"
                if is_dyn_import and _has_non_literal_arg(node):
                    cats.add("dynamic_require")
    return cats


def _find_proto_pollution(tree, added_lines):
    if tree is None:
        return False
    for node in _walk_tree(tree.root_node):
        lo = (node.start_point[0] + 1) if node.start_point else 1
        hi = (node.end_point[0] + 1) if node.end_point else lo
        if added_lines.isdisjoint(range(lo, hi + 1)):
            continue
        text = _node_text(node)
        if "__proto__" in text or "constructor.prototype" in text:
            if node.type in ("pair", "assignment_expression", "call_expression"):
                return True
    return False


@dataclass(frozen=True)
class FileFacts:
    path: str
    lines: tuple
    location_weight: float
    bound_categories: frozenset
    bound_names: frozenset
    imported_modules: frozenset
    blob_present: bool
    syntax_error: bool
    added_strs: tuple


@dataclass(frozen=True)
class DiffFacts:
    files: tuple
    binaries: tuple
    deps: tuple
    maintainer_changed: bool
    publisher_changed: bool = False
    low_footprint_publisher: bool = False
    package_json_changes: frozenset = frozenset()
    changed_scripts: frozenset = frozenset()
    lock_meta: dict = None
    changed_script_text: str = ""


def _file_facts(fd) -> FileFacts:
    added_strs = tuple(ln for h in fd.hunks for ln in h.added)
    added_lines = {j + 1 for h in fd.hunks for j in range(h.new_range[0], h.new_range[1])}
    lines = (fd.hunks[0].new_range[0] + 1, fd.hunks[-1].new_range[1])
    loc = classify_location(fd.path)
    if fd.new_text is None or not _is_js(fd.path):
        return FileFacts(fd.path, lines, loc, frozenset(), frozenset(), frozenset(), False, False, added_strs)
    tree = _parse_js(fd.new_text)
    if tree is None:
        blob = _blob_present(added_strs)
        return FileFacts(fd.path, lines, loc, frozenset(), frozenset(), frozenset(), blob, False, added_strs)
    try:
        cats, names = _find_categories(tree, added_lines)
        cats.update(_find_dynamic_imports(tree, added_lines))
        if _find_proto_pollution(tree, added_lines):
            cats.add("proto")
        blob = _blob_present(added_strs)
        return FileFacts(fd.path, lines, loc, frozenset(cats), frozenset(names),
                         frozenset(), blob, False, added_strs)
    except Exception:
        return FileFacts(fd.path, lines, loc, frozenset(), frozenset(), frozenset(), False, False, added_strs)


def _normalize_binaries(added_binaries):
    out = []
    for b in added_binaries:
        reason = b.get("reason")
        if not reason and b.get("sha256"):
            reason = "new-binary"
        out.append({**b, "reason": reason})
    return tuple(out)


def _roles_set(meta) -> set:
    return {r.lower() for r in (meta or {}).get("maintainers") or [] if r}


def build_facts(diff, maintainer_context=None) -> DiffFacts:
    files = tuple(_file_facts(fd) for fd in diff.changed if any(h.added for h in fd.hunks))
    maint = False
    publisher_changed = False
    low_footprint = False
    if maintainer_context:
        cur = _roles_set(maintainer_context.get("current"))
        prior = _roles_set(maintainer_context.get("prior"))
        maint = bool(cur and prior and cur != prior)
        current = maintainer_context.get("current") or {}
        publisher_changed = bool(current.get("publisher_changed"))
        low_footprint = bool(current.get("low_footprint_publisher"))
    pkg_fields = frozenset(c.field for c in diff.package_json_changes) if hasattr(diff, "package_json_changes") else frozenset()
    changed_scripts = getattr(diff, "_changed_scripts", frozenset())
    lock_meta = getattr(diff, "_lock_meta", {})
    return DiffFacts(files, _normalize_binaries(diff.added_binaries),
                     tuple(diff.added_dep_findings), maint, publisher_changed,
                     low_footprint, pkg_fields, changed_scripts, lock_meta,
                     getattr(diff, "_changed_script_text", ""))
