"""The hygiene gate from S-10, which P0-9 depends on.

Four rules, each of which caught a real defect in this tree:

1. **No bare `print` in library code.** The verifier carried fifteen `RADIX_DEBUG_VERIFY` prints
   in its reject paths. They are not security bugs on their own, but a library that writes to
   stdout cannot be embedded, its output cannot be trusted, and a debug print in a reject path is
   a signal that the path was being reasoned about by observation.
2. **No debug environment variables left in the library.** The same sites were guarded by an env
   var, which means they were invisible to review and live in release builds.
3. **No function defined twice in a module.** `tag_of`, `sign_tagged` and `verify_tagged` were each
   defined twice in `ring_signature.py`; the earlier definitions were silently dead, and a reader
   would have fixed the wrong one.
4. **No unreachable statement after `return` or `raise`.** A withdrawn tag path sat after a
   `return`, so it looked implemented while being impossible to reach.

These are cheap to check and they were all violated in a tree that passed 600 tests.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
LIBRARY = REPO / "radix_core"


def library_modules():
    for path in LIBRARY.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        yield path


def _is_main_guard(node):
    """`if __name__ == "__main__":` -- a script's own output is not library noise."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
        return False
    left = test.left
    comparator = test.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(comparator, ast.Constant)
        and comparator.value == "__main__"
    )


def _prints_outside_main(tree):
    found = []

    def walk(node):
        for field, value in ast.iter_fields(node):
            items = value if isinstance(value, list) else [value]
            for item in items:
                if not isinstance(item, ast.AST):
                    continue
                if _is_main_guard(item):
                    continue
                if (
                    isinstance(item, ast.Call)
                    and isinstance(item.func, ast.Name)
                    and item.func.id == "print"
                ):
                    found.append(item.lineno)
                walk(item)

    walk(tree)
    return found


def test_no_bare_print_in_library_code():
    offenders = []
    for path in library_modules():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for line in _prints_outside_main(tree):
            offenders.append(f"{path.relative_to(REPO)}:{line}")
    assert not offenders, "library code prints: " + ", ".join(offenders)


def test_no_debug_environment_variables_in_library_code():
    offenders = []
    for path in library_modules():
        text = path.read_text(encoding="utf-8")
        for name in ("RADIX_DEBUG_VERIFY", "RADIX_DBG", "RADIX_TRACE_DEBUG"):
            if name in text:
                offenders.append(f"{path.relative_to(REPO)}: {name}")
    assert not offenders, "debug env vars remain: " + ", ".join(offenders)


def test_no_function_is_defined_twice_in_a_module():
    offenders = []
    for path in library_modules():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a syntax error is another test's problem
            continue
        names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
        duplicates = {name for name in names if names.count(name) > 1}
        if duplicates:
            offenders.append(f"{path.relative_to(REPO)}: {sorted(duplicates)}")
    assert not offenders, "functions defined twice: " + ", ".join(offenders)


def _unreachable(tree):
    found = []
    for _field, value in ast.iter_fields(tree):
        if isinstance(value, list) and value and all(isinstance(v, ast.stmt) for v in value):
            for index, stmt in enumerate(value[:-1]):
                if isinstance(stmt, (ast.Return, ast.Raise)) and value[index + 1 :]:
                    found.append((stmt.lineno, value[index + 1].lineno))
        if isinstance(value, ast.AST):
            found.extend(_unreachable(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    found.extend(_unreachable(item))
    return found


def test_no_unreachable_statements_after_return():
    offenders = []
    for path in library_modules():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for dead_line, after_line in _unreachable(tree):
            offenders.append(f"{path.relative_to(REPO)}:{after_line} (after return at {dead_line})")
    assert not offenders, "unreachable code: " + ", ".join(offenders)
