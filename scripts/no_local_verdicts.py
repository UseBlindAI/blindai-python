#!/usr/bin/env python3
"""The public client may produce an allow in exactly one place: parsing a server response.

WHAT THIS DOES NOT CHECK -- read this before trusting a green run.

    This finds FABRICATED allows: a permissive verdict written as a literal. It cannot see a call
    that never asked, or one that reused an earlier answer, because neither contains a literal to
    find. A rollout middleware at 10% and a client-side verdict cache both pass this check
    cleanly, and both are bypasses.

    That half is behavioural and lives in `test_every_call_asks.py`: every public call either
    makes exactly one request or raises, and the decision it returns was built from the body
    served for THAT request. Green here plus green there is the invariant. Green here alone is
    half of it, and the half that shipped `rollout`.

EVIDENCE OF COVERAGE, so this claim meets the standard it is written to enforce.

    Verified against mutations on 2026-09-14, against the TypeScript client's built output:
      - a cache-shaped client (memoise on identical input)  -> 1 failure, the nonce assertion
      - a rollout-shaped client (skip nine calls in ten)     -> 2 failures, request count and nonce
    Both restored to a byte-identical source afterwards, clean run 7/7. This checker itself was
    run against purpose-built fixtures: `allow()` and `block()` pass, a parameter default of
    `blocked=False` fails, a dataclass field default of `final_action="allow"` fails, and a
    builder not named for the allow case returning `{"allowed": True}` fails.


An allow is what the policy says after every gate has run, not what a regex says before any has.
A client that decides on its own is a second enforcement engine, and a second enforcement engine
has to be kept honest -- which is the mistake `checkBatch` made by turning any error into an
allow, and the mistake `fast_mode` made by returning `is_safe=True` on a whitelist regex match.

This is a test rather than a review note because the failure mode is not carelessness, it is
convenience. Every one of the paths this forbids was added by someone with a good local reason,
and none of them imported anything that a dependency-based check would have noticed. The next one
will arrive the same way.

Scoped deliberately: run it against the PUBLIC CLIENT package only. Guardian runs gates and must
produce verdicts; the server decides and records. The rule is about the client.

    python no_local_verdicts.py <package-root> [--parser relative/path/to/parse.py]

Exit 1 and print every offending site, or exit 0.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

#: Keyword arguments and dict keys whose permissive value IS a verdict. Each maps to the literal
#: that means "this call may proceed". A `blocked=True` or `is_threat=True` is not listed: a client
#: refusing on its own is a customer's choice made in their own code, and it cannot be a bypass.
PERMISSIVE = {
    "is_safe": True,
    "allowed": True,
    "blocked": False,
    "is_threat": False,
    "action": "allow",
    "final_action": "allow",
}


#: A function whose name says "this builds the allow case" may build one: a test author calling
#: `allow()` has chosen it explicitly and their intent is on the page. This exempts the SHAPE, not
#: a path -- a fixture module is not trusted wholesale, each builder in it is judged by whether
#: someone had to ask for an allow to get one.
EXPLICIT_ALLOW_NAMES = {
    # Builders named for the allow case. A test author calling `allow()` has chosen it, and their
    # intent is on the page.
    "allow", "allowed", "make_allow", "build_allow", "_allow", "allow_result",
    # `flagged()` builds an allowed response that carries detected threats -- the case that catches
    # code gating on `is_threat` when it should gate on `blocked`. Named for what it builds.
    "flagged",
    # `malformed()` builds a body that is deliberately NOT an AuthorizeResponse, using the exact
    # field names the old broken client read. Its purpose is to be rejected: the client must raise
    # on it. Exempting it by name rather than by file keeps the exemption to this one shape.
    "malformed",
}


def _is_explicit_allow_builder(name: str) -> bool:
    return name.lower().lstrip("_").rstrip("_") in {n.lstrip("_") for n in EXPLICIT_ALLOW_NAMES}


def _offending(tree: ast.AST) -> list[tuple[int, str]]:
    """Every place in one syntax tree that states a permissive verdict as a literal.

    Two things are judged differently, which is the whole point of doing this with an AST:

    A permissive value as a PARAMETER DEFAULT is always wrong, including inside a builder named
    for the allow case. `def decision(blocked: bool = False)` hands out an allow to anyone who
    calls it without arguments, which is precisely "a fabricated allow that nobody asked for".

    A permissive value in the BODY of a function whose name states the allow case is fine, because
    reaching it required the caller to name it.
    """
    hits: list[tuple[int, str]] = []
    explicit_bodies: set[int] = set()

    for sub in ast.walk(tree):
        # Class-level field defaults. In Python this is THE way a permissive default gets written:
        # `@dataclass class Result: is_threat: bool = False`. It is the same defect as a parameter
        # default and is easy to miss precisely because it does not look like a function.
        if isinstance(sub, ast.ClassDef):
            for stmt in sub.body:
                target = value = None
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    target, value = stmt.target.id, stmt.value
                elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and \
                        isinstance(stmt.targets[0], ast.Name):
                    target, value = stmt.targets[0].id, stmt.value
                if (target in PERMISSIVE and isinstance(value, ast.Constant)
                        and value.value == PERMISSIVE[target]):
                    hits.append((value.lineno,
                                 f"{target}={value.value!r} as a FIELD DEFAULT on class "
                                 f"{sub.name} -- an allow nobody asked for"))

        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Defaults first: these are wrong wherever they appear, so they are collected before
            # the function's body can be exempted below.
            defaults = list(sub.args.defaults) + [d for d in sub.args.kw_defaults if d is not None]
            names = [a.arg for a in sub.args.args + sub.args.kwonlyargs]
            for default in defaults:
                if not isinstance(default, ast.Constant):
                    continue
                for arg_name in names:
                    if arg_name in PERMISSIVE and default.value == PERMISSIVE[arg_name]:
                        hits.append((default.lineno,
                                     f"{arg_name}={default.value!r} as a PARAMETER DEFAULT in "
                                     f"{sub.name}() -- an allow nobody asked for"))
                        break
            if _is_explicit_allow_builder(sub.name):
                explicit_bodies.update(
                    id(n) for n in ast.walk(sub) if n is not sub)

    for sub in ast.walk(tree):
        if id(sub) in explicit_bodies:
            continue
        if isinstance(sub, ast.Call):
            for kw in sub.keywords:
                if (kw.arg in PERMISSIVE and isinstance(kw.value, ast.Constant)
                        and kw.value.value == PERMISSIVE[kw.arg]
                        and id(kw.value) not in explicit_bodies):
                    hits.append((kw.value.lineno, f"{kw.arg}={kw.value.value!r}"))
        elif isinstance(sub, ast.Dict):
            for key, value in zip(sub.keys, sub.values):
                if (isinstance(key, ast.Constant) and key.value in PERMISSIVE
                        and isinstance(value, ast.Constant)
                        and value.value == PERMISSIVE[key.value]
                        and id(value) not in explicit_bodies):
                    hits.append((value.lineno, f'"{key.value}": {value.value!r}'))

    return sorted(set(hits))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="the client package to check")
    parser.add_argument("--parser", action="append", default=[],
                        help="path, relative to root, permitted to build a verdict from a "
                             "server response (repeatable)")
    args = parser.parse_args()

    exempt = {(args.root / p).resolve() for p in args.parser}
    for path in exempt:
        if not path.exists():
            print(f"error: --parser {path} does not exist; an exemption that names nothing is a "
                  "hole waiting for a file to be renamed into it", file=sys.stderr)
            return 2

    failures: list[str] = []
    checked = 0
    for path in sorted(args.root.rglob("*.py")):
        if path.resolve() in exempt:
            continue
        checked += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        except SyntaxError as exc:
            failures.append(f"{path}: could not parse ({exc.msg}); a file this cannot read is a "
                            "file this cannot vouch for")
            continue
        for lineno, what in _offending(tree):
            rel = path.relative_to(args.root)
            failures.append(f"{rel}:{lineno}: produces a verdict locally -- {what}")

    if failures:
        print(f"{len(failures)} local verdict(s). Only the response parser may say allow:\n",
              file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        return 1

    print(f"ok: {checked} files, no verdict produced outside the response parser")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
