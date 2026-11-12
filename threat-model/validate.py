"""Threat-model lane v1 — deterministic gate.

The threat model is code: `threat-model/app.tc.json` (Threat Composer format)
travels in the guarded repo and is diffed and reviewed like everything else.
This validator fails the gate if:
  (a) the file is invalid (JSON / minimal Threat Composer shape),
  (b) a trust boundary declared in threat-model/boundaries.yaml has no threat
      that tags it as [TB-ID] in a substantive statement (coverage check),
  (b2) a threat id repeats, a mitigation is a placeholder, or a threat from the
      base was removed or weakened (a STRIDE category, a boundary or a
      mitigation's text dropped), or
  (c) infra changed in this diff but the threat model was untouched
      (staleness heuristic — the demo's favorite trick).

No LLM anywhere in this file, on purpose: this is the deterministic backstop
the agentic lane (stride_agent.py, advisory) sits beside, not instead of.

Usage:
    python validate.py --model threat-model/app.tc.json \
        --boundaries threat-model/boundaries.yaml [--changed-files files.txt]
Exit 0 = pass, 1 = gate failure (reasons on stdout).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import pathlib
import re
import sys

import yaml

# Matched case-insensitively against the lower-cased path. fnmatch's "*" also
# matches "/", so "*.tf" covers main.tf and a/b/main.tf. Callers list changed
# files with --no-renames, so a renamed template shows under its old name too.
# shortcut: names only, not content; a template under an unlisted name (or a
# Helm/k8s manifest) is missed. Detect by parsed content if that matters.
INFRA_PATTERNS = ["infra/*", "*/infra/*", "deploy/*", "*/deploy/*",
                  "*template.y*ml", "*template.json", "*.template", "*infra*.y*ml",
                  "*.tf", "*.tf.json", "*.tfvars", "*.hcl", "*cdk.json", "*stack*.py",
                  "*serverless.y*ml", "*appspec*.y*ml", "*buildspec*.y*ml", "*samconfig.*",
                  "*dockerfile*", "*containerfile*", "*docker-compose*.y*ml",
                  "*compose.y*ml"]
MODEL_PATH = "threat-model/app.tc.json"   # repo-relative path of the model
MIN_STATEMENT_WORDS = 10   # beyond boundary ids and names: an actor, an action, an impact
MIN_CONTENT_WORDS = 6      # distinct words that are not filler: about two each for those
# Words that carry no actor, action or impact, so padding a statement with them
# does not make it substantive.
FILLER_WORDS = frozenset("""
a an the and or but nor so yet of to in on at by for from with without into onto over
under through via as is are was were be been being am it its this that these those there
here which who whom whose what when where why how than then if else not no can could may
might must shall should will would do does did done has have had any all each every some
such own same other another also only just very too more most less up down out off about
above below between after before again once we you he she they them their our your his her
""".split())
MIN_MITIGATION_WORDS = 2   # so "n/a", "none", "tbd" and "-" fail on length alone
PLACEHOLDER_MITIGATIONS = {"not applicable", "not needed", "no mitigation", "to do",
                           "none yet"}
_C_ESCAPES = {b"a": b"\a", b"b": b"\b", b"t": b"\t", b"n": b"\n", b"v": b"\v",
              b"f": b"\f", b"r": b"\r"}


def _norm(text) -> str:
    return " ".join(str(text).split()).casefold()


def _placeholder(mitigation) -> bool:
    """Empty, 'n/a', 'none' and the like record no mitigation at all."""
    text = _norm(mitigation).strip(" .")
    return (not isinstance(mitigation, str) or text in PLACEHOLDER_MITIGATIONS
            or len(re.findall(r"[A-Za-z][A-Za-z'-]+", text)) < MIN_MITIGATION_WORDS)


def load_model(path: pathlib.Path) -> tuple[dict | None, list[str]]:
    errors: list[str] = []
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return None, [f"threat model missing: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"threat model is not valid JSON: {exc}"]
    if not isinstance(doc, dict):
        return None, ["threat model root must be a JSON object"]
    threats = doc.get("threats")
    if not isinstance(threats, list) or not threats:
        errors.append("threat model has no threats[] — an empty model is not a model")
    for i, t in enumerate(threats or []):
        if not isinstance(t, dict) or not t.get("statement"):
            errors.append(f"threats[{i}] missing 'statement'")
        elif not (isinstance(t.get("stride"), list) and t["stride"]
                  and isinstance(t.get("mitigations"), list) and t["mitigations"]):
            # A threat is more than a sentence that names a boundary.
            errors.append(f"threats[{i}] ({t.get('id', '?')}) needs non-empty 'stride' "
                          f"and 'mitigations' lists")
        elif any(_placeholder(m) for m in t["mitigations"]):
            errors.append(f"threats[{i}] ({t.get('id', '?')}) has a placeholder mitigation "
                          f"(empty, 'n/a', 'none' or under {MIN_MITIGATION_WORDS} words) — "
                          f"say what mitigates it, or why it no longer applies")
    # A repeated id hides the threat the base comparison reads past.
    ids = [str(t.get("id")) for t in threats or [] if isinstance(t, dict) and t.get("id")]
    repeated = sorted({i for i in ids if ids.count(i) > 1})
    if repeated:
        errors.append(f"threat ids must be unique: {', '.join(repeated)} appear more than once")
    return doc, errors


def _threat_ids(model: dict) -> set:
    return {str(t.get("id")) for t in model.get("threats", [])
            if isinstance(t, dict) and t.get("id")}


def removed_threats(model: dict, base: dict | None) -> list[str]:
    """A PR may change a threat but not delete one; deleting is a maintainer's call."""
    if not base:
        return []
    gone = sorted(_threat_ids(base) - _threat_ids(model))
    errors = [f"threats removed since the base: {', '.join(gone)} — keep them and record "
              f"in 'mitigations' why they no longer apply"] if gone else []
    # Gutting a threat is removing it under the same id: an edit may reword the
    # statement and add, but not drop a STRIDE category or boundary, shrink its
    # mitigations, or lose a mitigation's text (it may be extended, not replaced).
    # Every head entry under an id is checked, so a pristine copy appended under a
    # repeated id cannot stand in for the gutted one.
    # shortcut: a statement rewritten around its TB- tokens still passes; flag
    # material rewrites for a maintainer if that matters.
    now: dict[str, list] = {}
    for t in model.get("threats", []):
        if isinstance(t, dict):
            now.setdefault(str(t.get("id")), []).append(t)
    weakened = []
    for old in base.get("threats", []):
        if not isinstance(old, dict):
            continue
        for new in now.get(str(old.get("id")), []):
            texts = [_norm(m) for m in new.get("mitigations") or []]
            if (not set(old.get("stride") or []) <= set(new.get("stride") or [])
                    or not set(re.findall(r"TB-[A-Z]+", str(old.get("statement", ""))))
                    <= set(re.findall(r"TB-[A-Z]+", str(new.get("statement", ""))))
                    or len(texts) < len(old.get("mitigations") or [])
                    or not all(any(_norm(m) in t for t in texts)
                               for m in old.get("mitigations") or [])):
                weakened.append(str(old.get("id")))
                break
    if weakened:
        errors.append(f"threats weakened since the base: {', '.join(weakened)} — a STRIDE "
                      f"category, a boundary or a mitigation was dropped; that is a "
                      f"maintainer's call, like removing the threat")
    return errors


def _substantive(statement: str, boundaries) -> bool:
    """At least MIN_STATEMENT_WORDS words, MIN_CONTENT_WORDS of them distinct and
    not filler, once boundary ids and names are removed."""
    # shortcut: distinct invented words still count, and coverage is not tied to
    # the boundaries the PR touches (boundaries.yaml maps no paths); add a path
    # map per boundary to require a threat on the changed one.
    text = re.sub(r"TB-[A-Z]+", " ", statement)
    for _, name in boundaries:
        if name:
            text = re.sub(re.escape(name), " ", text, flags=re.I)
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z'-]+", text)]
    return (len(words) >= MIN_STATEMENT_WORDS
            and len({w for w in words if w not in FILLER_WORDS}) >= MIN_CONTENT_WORDS)


def boundary_coverage(model: dict, boundaries_path: pathlib.Path) -> list[str]:
    try:
        declared = yaml.safe_load(boundaries_path.read_text()) or {}
    except FileNotFoundError:
        # A deleted or mistyped boundaries file must not read as "all covered".
        return [f"boundaries file missing: {boundaries_path}"]
    if not isinstance(declared, dict) or not declared.get("boundaries"):
        return [f"boundaries file declares no boundaries: {boundaries_path}"]
    errors = []
    boundaries = [(str(b.get("id", "")), str(b.get("name", "")))
                  for b in declared.get("boundaries", []) if isinstance(b, dict)]
    # Only a real threat counts as covering a boundary: its own statement tags
    # the boundary as [TB-ID] (the form every shipped threat uses; a name or id in
    # passing prose is not a reference) and says something beyond boundary tokens
    # and filler, and it has STRIDE categories and mitigations. A mention in the
    # app description, a mitigation note, or a statement stuffed with ids does not.
    covering = [str(t.get("statement", "")) for t in model.get("threats", [])
                if isinstance(t, dict) and t.get("stride") and t.get("mitigations")
                and _substantive(str(t.get("statement", "")), boundaries)]
    ids = {bid for bid, _ in boundaries if bid}
    for bid, name in boundaries:
        if not any(bid and f"[{bid}]" in text for text in covering):
            errors.append(
                f"trust boundary '{bid or name}' declared in boundaries.yaml has no "
                f"threat tagging it as [{bid or 'TB-ID'}] — add a threat or remove the boundary")
    # The other direction, which used to go unchecked: a threat can name a
    # boundary that was never declared, and the model looks complete because
    # coverage only ran declared -> referenced. TB-CONTROL sat referenced by two
    # threats and undeclared for weeks that way.
    for ref in sorted({m for t in model.get("threats", [])
                       for m in re.findall(r"TB-[A-Z]+", t.get("statement", ""))}):
        if ref not in ids:
            errors.append(
                f"trust boundary '{ref}' is referenced by a threat but not declared "
                f"in boundaries.yaml — declare it or stop referencing it")
    return errors


def _unquote(path: str) -> str:
    """git C-quotes a name with non-ASCII or special bytes ("infra/ma\\303\\255n.tf");
    decode it so the infra patterns see the real name."""
    if len(path) < 2 or path[0] != '"' or path[-1] != '"':
        return path
    raw = re.sub(rb'\\(?:([0-3][0-7]{2})|(.))',
                 lambda m: bytes([int(m[1], 8)]) if m[1] else _C_ESCAPES.get(m[2], m[2]),
                 path[1:-1].encode())
    return raw.decode("utf-8", "replace")


def staleness(changed_files: list[str], model: dict | None = None,
              base: dict | None = None) -> list[str]:
    changed_files = [_unquote(f) for f in changed_files]
    if not changed_files:
        return []
    infra_changed = [f for f in changed_files
                     if any(fnmatch.fnmatchcase(f.lower(), p) for p in INFRA_PATTERNS)]
    # Only the model itself counts, and only a real edit: a touched README under
    # threat-model/, or the same JSON re-indented, is not a reviewed model.
    tm_changed = MODEL_PATH in changed_files and not (
        model is not None and base is not None and model == base)
    if infra_changed and not tm_changed:
        return [(f"infra changed ({', '.join(infra_changed[:5])}) but threat-model/ "
                 f"was untouched — update app.tc.json or record why no new threats apply")]
    return []


def main() -> int:
    p = argparse.ArgumentParser(description="Deterministic threat-model gate")
    p.add_argument("--model", required=True)
    p.add_argument("--boundaries", required=True)
    p.add_argument("--changed-files", help="newline-separated list of changed paths")
    p.add_argument("--base-model", help="the model at the PR's base, to catch deleted "
                                        "threats and no-op edits (a missing file is skipped)")
    args = p.parse_args()

    model, errors = load_model(pathlib.Path(args.model))
    base = None
    if args.base_model and pathlib.Path(args.base_model).is_file() \
            and pathlib.Path(args.base_model).stat().st_size:
        try:
            base = json.loads(pathlib.Path(args.base_model).read_text())
        except json.JSONDecodeError:
            base = None
    if model is not None:
        errors += boundary_coverage(model, pathlib.Path(args.boundaries))
        errors += removed_threats(model, base)
    if args.changed_files:
        changed = [l.strip() for l in
                   pathlib.Path(args.changed_files).read_text().splitlines() if l.strip()]
        errors += staleness(changed, model, base)

    if errors:
        print("THREAT-MODEL GATE: FAIL")
        for e in errors:
            print(f"  - {e}")
        return 1
    n = len(model.get("threats", [])) if model else 0
    print(f"THREAT-MODEL GATE: PASS ({n} threats, boundaries covered, model fresh)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
