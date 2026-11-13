"""Chunked review: one verdict over many chunks, failing closed on any gap.

The plans here come from the real planner (pipeline_tools/review_chunks.py),
so the consumer is tested against what the pipeline actually writes. Models
are fakes that answer from markers in the diff they are shown.
"""
import ast
import hashlib
import json
import re
import shlex
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from conftest import ROOT
from reviewer import chunked
from reviewer.bedrock_reviewer import ReviewOutcome
from reviewer.rules import load_rules
from reviewer.verdict import Finding, GateResult, Verdict

RULES = ROOT / ".reviewer.yaml"
RS = load_rules(RULES.read_text())
LIMIT = 6_000
SECURITY, QUALITY, ARCHITECTURE, ACCESSIBILITY = (a.name for a in RS.agents)
ACCESSIBILITY_PATTERNS = RS.agents[3].file_patterns


@pytest.fixture
def planner(load_module):
    return load_module("pipeline_tools/review_chunks.py")


@pytest.fixture
def fake(monkeypatch):
    model = FakeBedrock()
    monkeypatch.setattr(chunked, "bedrock_client", lambda region, **kw: model)
    yield model
    model.release.set()  # free any thread a deadline test abandoned


def added(path, lines):
    body = "".join(f"+{line}\n" for line in lines)
    return (f"diff --git a/{path} b/{path}\nnew file mode 100644\nindex 0000000..1111111\n"
            f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + body)


def filler(n, tag="v"):
    return [f"const {tag}{i} = {i}; // {'.' * 40}" for i in range(n)]


def site(**special):
    """Six JS modules (several chunks at LIMIT) plus index.html and style.css."""
    files = {f"web/m{i}.js": filler(60, f"m{i}_") for i in range(6)}
    files["web/index.html"] = ["<main><h1>Troy</h1></main>"]
    files["web/style.css"] = ["body { color: #111; }"]
    for path, line in special.items():
        # Same size as the others, so every module still fills its own chunk.
        files[path.replace("__", "/").replace("_js", ".js")] = filler(30) + [line] + filler(29, "w")
    return "".join(added(path, lines) for path, lines in files.items())


def write_plan(planner, tmp_path, diff, limit=LIMIT):
    out = tmp_path / "review-input"
    out.mkdir(exist_ok=True)
    planner.write_plan(planner.plan(diff, limit), diff, limit, out)
    return out / "chunk-plan.json"


def response(text, stop="end_turn"):
    return {"output": {"message": {"content": [{"text": text}]}}, "stopReason": stop}


class FakeBedrock:
    """Converse stand-in. Markers in a file section steer the seat that owns them.

    BLOCK_ME (.js)  -> SEC-003, blocking, from the Security seat
    ROBUST_ME       -> ROB-201, advisory, from the Code Quality seat
    TRUNCATE_SEC / TRUNCATE_ROB -> that seat's answer stops at max_tokens
    TOO_MANY        -> 26 Security findings, over max_findings
    HANG_ME         -> the call waits until `release` is set
    FLAKY_SEC       -> the Security seat's FIRST discovery call for that file raises
    FLAKY_HANG      -> like FLAKY_SEC, and every later call waits until `release`
    """

    def __init__(self, delay=0.0):
        self.calls, self.lock, self.active, self.peak = [], threading.Lock(), 0, 0
        self.delay, self.release = delay, threading.Event()
        self.flaky = {}
        self.exceptions = SimpleNamespace(
            ValidationException=type("ValidationException", (Exception,), {}))

    def converse(self, **kw):
        with self.lock:
            self.calls.append(kw)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.delay)
            return self.answer(kw["system"][0]["text"], kw["messages"][0]["content"][0]["text"])
        finally:
            with self.lock:
                self.active -= 1

    def answer(self, system, user):
        if "validation stage" in system:
            block = re.search(r"<untrusted-candidates-\w+>\n(.*?)\n</untrusted-candidates", user, re.S)
            return response(json.dumps({"scores": [{"index": c["index"], "confidence": 95}
                                                   for c in json.loads(block[1])]}))
        security, quality = "SEC-003:" in system, "ROB-201:" in system
        findings = []
        for section in re.split(r"(?m)^(?=diff --git )", user):
            match = re.match(r"diff --git a/(\S+) b/", section)
            if not match:
                continue
            path = match[1]
            if "HANG_ME" in section:
                self.release.wait(30)
            if security and ("FLAKY_SEC" in section or "FLAKY_HANG" in section):
                with self.lock:
                    seen = self.flaky[path] = self.flaky.get(path, 0) + 1
                if seen == 1:
                    raise RuntimeError("ThrottlingException: Rate exceeded")
                if "FLAKY_HANG" in section:
                    self.release.wait(30)
            if (security and "TRUNCATE_SEC" in section) or (quality and "TRUNCATE_ROB" in section):
                return response('{"findings": [', stop="max_tokens")
            if security and "BLOCK_ME" in section and path.endswith(".js"):
                findings.append({"rule_id": "SEC-003", "path": path, "line": 21,
                                 "message": "location.hash reaches innerHTML",
                                 "suggested_code": None})
            if security and "TOO_MANY" in section:
                findings += [{"rule_id": "SEC-002", "path": path, "line": i, "message": "m",
                              "suggested_code": None} for i in range(26)]
            if quality and "ROBUST_ME" in section:
                findings.append({"rule_id": "ROB-201", "path": path, "line": 21,
                                 "message": "fetch() result ignored", "suggested_code": None})
        return response(json.dumps({"findings": findings}))


def run_cli(load_module, monkeypatch, tmp_path, diff, plan_path, *extra, rules=RULES, cli=None):
    cli = cli or load_module("agent/review_cli.py")
    diff_file = tmp_path / "change.diff"
    diff_file.write_text(diff)
    report = tmp_path / "findings.json"
    monkeypatch.setattr(sys, "argv", ["review_cli", "--diff", str(diff_file), "--rules", str(rules),
                                      "--chunk-plan", str(plan_path), "--report", str(report),
                                      *extra])
    code = cli.main()
    return code, json.loads(report.read_text())


def seat(report, name):
    return next(a for a in report["agents"] if a["name"] == name)


# --- the plan the reviewer reads must prove complete coverage --------------------

def test_plan_round_trips_through_independent_verification(planner, tmp_path):
    diff = site()
    plan = chunked.load_plan(write_plan(planner, tmp_path, diff), diff)
    assert len(plan.chunks) > 2
    assert plan.chunk_bytes == LIMIT
    assert all(len(c.text.encode()) <= LIMIT for c in plan.chunks)
    paths = {u.path for c in plan.chunks for u in c.units}
    assert {"web/index.html", "web/style.css", "web/m0.js"} <= paths


def rewrite(plan_path, mutate):
    doc = json.loads(plan_path.read_text())
    mutate(doc, plan_path.parent)
    plan_path.write_text(json.dumps(doc))


def put_chunk(root, row, data):
    (root / row["path"]).write_bytes(data)
    row["bytes"], row["sha256"] = len(data), hashlib.sha256(data).hexdigest()


def drop_last_section(doc, root):
    row = next(r for r in doc["chunks"] if len(r["units"]) > 1)
    data = (root / row["path"]).read_bytes()
    put_chunk(root, row, data[:sum(u["bytes"] for u in row["units"][:-1])])
    row["units"] = row["units"][:-1]


def repeat_a_section(doc, root):
    row = doc["chunks"][0]
    first = row["units"][0]
    data = (root / row["path"]).read_bytes()[:first["bytes"]]
    extra = {"index": len(doc["chunks"]), "path": f"chunks/{len(doc['chunks']):04d}.diff",
             "units": [dict(first)]}
    put_chunk(root, extra, data)
    doc["chunks"].append(extra)


def flip_a_byte(doc, root):
    path = root / doc["chunks"][1]["path"]
    data = bytearray(path.read_bytes())
    data[-3] ^= 1
    path.write_bytes(bytes(data))


def edit_content_consistently(doc, root):
    row = doc["chunks"][1]
    data = (root / row["path"]).read_bytes().replace(b"const m", b"const n", 1)
    put_chunk(root, row, data)


def test_a_part_split_mid_line_is_rejected(planner, tmp_path):
    # Continuum, 2026-11-07: moving the tail of part 1's last line into part 2
    # still rebuilds the diff, but leaves part 1 ending mid-line, where the
    # next part's repeated header could be read as a new file section.
    diff = added("web/big.js", filler(300))
    plan_path = write_plan(planner, tmp_path, diff)

    def split_mid_line(doc, root):
        units = [(row, i, u) for row in doc["chunks"] for i, u in enumerate(row["units"])]
        (row1, i1, u1), (row2, i2, u2) = [x for x in units if x[2]["part"] in (1, 2)][:2]
        assert u1["parts"] >= 2 and row1 is not row2

        def bounds(row, i):
            start = sum(u["bytes"] for u in row["units"][:i])
            return start, start + row["units"][i]["bytes"]

        data1 = (root / row1["path"]).read_bytes()
        s1, e1 = bounds(row1, i1)
        tail, data1 = data1[e1 - 5:e1], data1[:e1 - 5] + data1[e1:]
        u1["bytes"] -= 5
        put_chunk(root, row1, data1)
        data2 = (root / row2["path"]).read_bytes()
        s2, _ = bounds(row2, i2)
        cut = s2 + u2["header_bytes"]
        put_chunk(root, row2, data2[:cut] + tail + data2[cut:])
        u2["bytes"] += 5

    rewrite(plan_path, split_mid_line)
    with pytest.raises(chunked.PlanVerificationError, match="mid-line"):
        chunked.load_plan(plan_path, diff)


def header_swallows_a_hunk(doc, root):
    unit = doc["chunks"][0]["units"][0]
    unit["header_bytes"] = unit["bytes"]


def renumber_a_hunk_header(doc, root):
    # Continuum, 2026-11-07: the proof ignored @@ lines, so a plan could change
    # them (same length here, so every size still matches) and still verify.
    row = doc["chunks"][0]
    data = (root / row["path"]).read_bytes()
    assert b"@@ -0,0 +1," in data
    put_chunk(root, row, data.replace(b"@@ -0,0 +1,", b"@@ -0,0 +9,", 1))


@pytest.mark.parametrize("mutate, reason", [
    (drop_last_section, "skips|exactly once|reproduce"),
    (repeat_a_section, "repeats"),
    (flip_a_byte, "does not match the plan"),
    (edit_content_consistently, "reproduce the diff"),
    (header_swallows_a_hunk, "malformed file section"),
    (renumber_a_hunk_header, "hunk headers do not follow"),
    (lambda doc, root: doc["chunks"][0]["units"][0].update(path="web/other.js"),
     "another path"),
    (lambda doc, root: doc["chunks"].clear(), "exactly when the diff is non-empty"),
    (lambda doc, root: doc["chunks"][0].update(path="../change.diff"), "invalid file name"),
    (lambda doc, root: doc.update(diff_sha256="0" * 64), "different diff"),
    (lambda doc, root: doc.update(version=2), "unsupported version"),
    (lambda doc, root: doc.update(chunk_bytes=True), "invalid"),
])
def test_incomplete_or_tampered_plan_is_rejected(planner, tmp_path, mutate, reason):
    diff = site()
    plan_path = write_plan(planner, tmp_path, diff)
    rewrite(plan_path, mutate)
    with pytest.raises(chunked.PlanVerificationError, match=reason):
        chunked.load_plan(plan_path, diff)


@pytest.mark.parametrize("policy", ["panel", "advisory-only"])
def test_unverifiable_plan_blocks_whatever_the_policy(planner, tmp_path, monkeypatch,
                                                       load_module, fake, policy):
    rules = RULES
    if policy == "advisory-only":
        rules = tmp_path / "advisory.yaml"
        rules.write_text("version: 1\nagents:\n  - name: Design\n    rules: [DES-]\n"
                         "defaults: {fail_mode: open}\nrules:\n  - id: DES-001\n"
                         "    description: layering\n    blocking: false\n")
    diff = site()
    plan_path = write_plan(planner, tmp_path, diff)
    rewrite(plan_path, flip_a_byte)
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff, plan_path, rules=rules)
    assert (code, report["verdict"]) == (1, "BLOCKED_ERROR")
    assert "chunk plan failed verification" in report["error"]
    assert all(a["error"] for a in report["agents"])
    assert fake.calls == []


# --- which seat reviews what ------------------------------------------------------

def test_every_unscoped_seat_reviews_every_chunk_and_scoped_files_stay_together(planner, tmp_path):
    diff = site()
    plan = chunked.load_plan(write_plan(planner, tmp_path, diff), diff)
    for agent in RS.agents:
        items = chunked.seat_items(plan, agent)
        if agent.file_patterns:
            [item] = items
            assert item.files == ("web/index.html", "web/style.css")
            assert len(item.chunks) >= 1
        else:
            assert [i.text for i in items] == [c.text for c in plan.chunks]


def test_a_scoped_item_cap_splits_only_a_scoped_seats_view_and_loses_nothing(planner, tmp_path):
    pages = {f"web/p{i}.html": [f"<p>{i}-{j} {'.' * 40}</p>" for j in range(40)] for i in range(5)}
    diff = site() + "".join(added(path, lines) for path, lines in pages.items())
    plan = chunked.load_plan(write_plan(planner, tmp_path, diff), diff)
    agent = RS.agents[3]
    default = chunked.seat_items(plan, agent)
    capped = chunked.seat_items(plan, agent, 2_500)
    assert all(i.nbytes <= plan.chunk_bytes for i in default)
    assert len(capped) > len(default) and len(capped) >= 5     # every page on its own
    assert all(i.nbytes <= 2_500 or len(i.files) == 1 for i in capped)
    # The same in-scope text, in diff order, each section exactly once.
    assert "".join(i.text for i in capped) == "".join(i.text for i in default)
    assert [f for i in capped for f in i.files] == [f for i in default for f in i.files]
    for unscoped in RS.agents[:3]:      # unscoped seats keep the plan's chunks
        assert chunked.seat_items(plan, unscoped, 2_500) == chunked.seat_items(plan, unscoped)
    assert chunked.seat_items(plan, agent, plan.chunk_bytes) == default
    for bad in (0, -1, plan.chunk_bytes + 1, 2.5, "5000", True):
        with pytest.raises(ValueError, match="scoped_item_bytes"):
            chunked.seat_items(plan, agent, bad)
    capped_schedule = chunked.schedule(plan, RS, scoped_item_bytes=2_500)
    assert [s["reviews"] for s in capped_schedule["seats"]][3] == len(capped)
    assert chunked.schedule(plan, RS) == chunked.schedule(plan, RS, scoped_item_bytes=None)


def test_dry_run_prints_the_schedule_without_any_model_call(planner, tmp_path, monkeypatch,
                                                           load_module, capsys):
    diff = site()
    plan_path = write_plan(planner, tmp_path, diff)
    (tmp_path / "change.diff").write_text(diff)
    cli = load_module("agent/review_cli.py")
    monkeypatch.setattr(sys, "argv", ["review_cli", "--dry-run", "--diff", str(tmp_path / "change.diff"),
                                      "--rules", str(RULES), "--chunk-plan", str(plan_path)])
    assert cli.main() == 0      # conftest refuses boto3.client: no client was built
    schedule = json.loads(capsys.readouterr().out)
    reviews = {s["name"]: s["reviews"] for s in schedule["seats"]}
    assert reviews[SECURITY] == reviews[QUALITY] == reviews[ARCHITECTURE] == schedule["chunks"]
    assert reviews[ACCESSIBILITY] == 1


# --- one verdict, today's semantics -----------------------------------------------

def test_blocking_finding_in_one_chunk_fails_the_gate(planner, tmp_path, monkeypatch,
                                                     load_module, fake):
    diff = site(web__m4_js="el.innerHTML = location.hash; // BLOCK_ME")
    plan_path = write_plan(planner, tmp_path, diff)
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff, plan_path,
                           "--workers", "8", "--deadline-seconds", "4920")
    assert (code, report["verdict"]) == (1, "FAIL")
    security = seat(report, SECURITY)
    assert (security["verdict"], security["blocking"], security["error"]) == ("FAIL", 1, None)
    assert len(security["chunks"]) == report["chunking"]["chunks"] > 2
    assert all(row["verdict"] in ("PASS", "FAIL") for row in security["chunks"])
    [finding] = [f for f in report["findings"] if f["blocking"]]
    assert (finding["path"], finding["agent"], finding["confidence"]) == ("web/m4.js", SECURITY, 95)
    assert "web/m4.js" in security["chunks"][finding["chunk"]]["files"]
    assert report["stats"]["blocking"] == 1
    assert {a["verdict"] for a in report["agents"] if a["name"] != SECURITY} == {"PASS"}
    assert report["chunking"]["reviews_completed"] == report["chunking"]["reviews_scheduled"]


def test_truncated_answer_in_any_chunk_fails_closed_and_keeps_evidence(
        planner, tmp_path, monkeypatch, load_module, fake):
    diff = site(web__m1_js="// TRUNCATE_SEC", web__m4_js="el.innerHTML = location.hash; // BLOCK_ME")
    plan_path = write_plan(planner, tmp_path, diff)
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff, plan_path)
    assert (code, report["verdict"]) == (1, "BLOCKED_ERROR")
    security = seat(report, SECURITY)
    assert security["verdict"] == "BLOCKED_ERROR"
    assert "stopReason=max_tokens" in security["error"] and "web/m1.js" in security["error"]
    assert security["blocking"] == 1      # the other chunk's finding is still reported
    # The error was retried once, ended in the same error, and both are on record.
    [row] = [r for r in security["chunks"] if r["verdict"] == "BLOCKED_ERROR"]
    assert row["attempts"] == 2 and "stopReason=max_tokens" in row["earlier_errors"][0]
    assert report["chunking"]["retries"] == report["chunking"]["retries_completed"] == 1


def test_more_findings_than_one_call_allows_fails_closed(planner, tmp_path, monkeypatch,
                                                        load_module, fake):
    diff = site(web__m2_js="// TOO_MANY")
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff))
    assert (code, report["verdict"]) == (1, "BLOCKED_ERROR")
    assert "max_findings" in seat(report, SECURITY)["error"]


def test_advisory_seat_error_is_advisory_error_as_in_a_single_call(
        planner, tmp_path, monkeypatch, load_module, fake):
    diff = site(web__m3_js="// TRUNCATE_ROB")
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff))
    quality = seat(report, QUALITY)
    assert quality["verdict"] == "ADVISORY_ERROR" and "web/m3.js" in quality["error"]
    assert (code, report["verdict"]) == (0, "ADVISORY_ERROR")
    # Identical to what one call over the whole diff yields for this seat today.
    single = chunked.review_diff(diff, RS, client=FakeBedrock(), agent=RS.agents[1]).result
    assert single.verdict == Verdict.ADVISORY_ERROR


def test_chunks_unfinished_at_the_deadline_fail_closed_and_return_promptly(
        planner, tmp_path, monkeypatch, load_module, fake):
    diff = site(web__m2_js="// HANG_ME")
    started = time.monotonic()
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff),
                           "--workers", "4", "--deadline-seconds", "1")
    assert time.monotonic() - started < 10
    assert (code, report["verdict"]) == (1, "BLOCKED_ERROR")
    assert report["chunking"]["deadline_reached"] is True
    security = seat(report, SECURITY)
    assert "not reviewed before the review deadline" in security["error"]
    assert any(row["verdict"] is None for row in security["chunks"])
    assert seat(report, ARCHITECTURE)["verdict"] == "ADVISORY_ERROR"


def test_a_review_that_errors_once_is_retried_and_both_attempts_recorded(
        planner, tmp_path, monkeypatch, load_module, fake):
    diff = site(web__m2_js="// FLAKY_SEC")
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff))
    assert (code, report["verdict"]) == (0, "PASS")
    security = seat(report, SECURITY)
    assert (security["verdict"], security["error"]) == ("PASS", None)
    [row] = [r for r in security["chunks"] if r["attempts"] == 2]
    assert "web/m2.js" in row["files"] and (row["verdict"], row["error"]) == ("PASS", None)
    assert "ThrottlingException" in row["earlier_errors"][0]
    assert sum(r["attempts"] for r in security["chunks"]) == len(security["chunks"]) + 1
    c = report["chunking"]
    assert (c["retries"], c["retries_completed"]) == (1, 1)
    assert c["reviews_completed"] == c["reviews_scheduled"] and c["deadline_reached"] is False


def test_a_fail_is_final_and_never_retried(planner, tmp_path, monkeypatch, load_module, fake):
    diff = site(web__m4_js="el.innerHTML = location.hash; // BLOCK_ME")
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff))
    assert (code, report["verdict"]) == (1, "FAIL")
    assert report["chunking"]["retries"] == 0
    assert all(r["attempts"] == 1 for a in report["agents"] for r in a["chunks"])
    discoveries = [kw for kw in fake.calls if "SEC-003:" in kw["system"][0]["text"]
                   and "validation stage" not in kw["system"][0]["text"]
                   and "BLOCK_ME" in kw["messages"][0]["content"][0]["text"]]
    assert len(discoveries) == 1


def test_a_retry_unfinished_at_the_deadline_fails_closed_with_the_first_error(
        planner, tmp_path, monkeypatch, load_module, fake):
    diff = site(web__m2_js="// FLAKY_HANG")
    started = time.monotonic()
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff),
                           "--workers", "4", "--deadline-seconds", "2")
    assert time.monotonic() - started < 10
    assert (code, report["verdict"]) == (1, "BLOCKED_ERROR")
    security = seat(report, SECURITY)
    [row] = [r for r in security["chunks"] if r.get("retry")]
    assert row["attempts"] == 1 and "ThrottlingException" in row["error"]
    assert "retry unfinished at the review deadline" in security["error"]
    assert report["chunking"]["deadline_reached"] is True


def test_every_chunked_report_states_what_a_pass_does_not_cover(
        planner, tmp_path, monkeypatch, load_module, fake):
    diff = site()
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff))
    assert (code, report["verdict"]) == (0, "PASS")
    note = report["chunking"]["note"]
    assert "not traced" in note and "per chunk call" in note and "binary_sections" in note


@pytest.mark.parametrize("separator", ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85",
                                       "\u2028", "\u2029"])
def test_file_content_cannot_fake_a_header_in_a_scoped_seats_view(planner, tmp_path, separator):
    # str.splitlines() breaks at these characters; the scoped view must not,
    # or the trap below would vanish from the Accessibility seat's input.
    page = added("web/index.html", ["<main>", f"x{separator}diff --git a/zz.js b/zz.js",
                                    "<div onclick=go()>trap</div>", "</main>"])
    diff = page + "".join(added(f"web/m{i}.js", filler(60)) for i in range(3))
    assert chunked._scope_diff(diff, ACCESSIBILITY_PATTERNS) == page
    plan = chunked.load_plan(write_plan(planner, tmp_path, diff), diff)
    [item] = chunked.seat_items(plan, RS.agents[3])
    assert item.text == page and "<div onclick=go()>trap</div>" in item.text


def test_worker_pool_bounds_concurrent_model_calls(planner, tmp_path):
    diff = site()
    plan = chunked.load_plan(write_plan(planner, tmp_path, diff), diff)
    model = FakeBedrock(delay=0.05)
    result = chunked.review_panel_chunked(plan, RS, client=model, workers=3, emit=lambda line: None)
    assert 1 < model.peak <= 3
    assert all(o.result.verdict == Verdict.PASS for _, o in result.panel)
    # Every unscoped seat saw every chunk exactly once.
    reviewed = [kw["messages"][0]["content"][0]["text"] for kw in model.calls]
    for chunk in plan.chunks:
        assert sum(chunk.text in text for text in reviewed) == 3


def test_merge_dedupes_across_chunks_keeping_the_strongest_copy():
    def finding(rule, confidence, line=3):
        return Finding(rule, "web/a.js", line, "m", confidence, "high", True)
    items = [chunked.SeatItem(0, "a", (0,), ("web/a.js (part 1/2)",)),
             chunked.SeatItem(1, "b", (1,), ("web/a.js (part 2/2)",))]
    outcomes = [
        (ReviewOutcome(GateResult(Verdict.FAIL, (finding("SEC-003", 85),), 2), "m", 2), 1.0),
        (ReviewOutcome(GateResult(Verdict.FAIL, (finding("SEC-003", 97),
                                                 finding("SEC-002", 90, 9)), 1), "m", 3), 2.0),
    ]
    outcome, rows, where, duplicates = chunked.merge_seat(RS.agents[0], RS, items, outcomes)
    result = outcome.result
    assert result.verdict == Verdict.FAIL and result.error is None
    assert [(f.rule_id, f.confidence) for f in result.findings] == [("SEC-003", 97), ("SEC-002", 90)]
    assert (where, duplicates) == ([1, 1], 1)
    assert (result.suppressed_below_threshold, outcome.discovery_count) == (3, 5)
    assert [row["verdict"] for row in rows] == ["FAIL", "FAIL"]


@pytest.mark.parametrize("index, expected", [(0, Verdict.BLOCKED_ERROR), (2, Verdict.ADVISORY_ERROR)])
def test_missing_chunk_is_never_a_pass(index, expected):
    items = [chunked.SeatItem(0, "a", (0,), ("a.js",)), chunked.SeatItem(1, "b", (1,), ("b.js",))]
    passed = (ReviewOutcome(GateResult(Verdict.PASS, (), 0), "m", 0), 1.0)
    outcome, rows, _, _ = chunked.merge_seat(RS.agents[index], RS, items, [passed, None],
                                             missing="not reviewed before the review deadline (9s)")
    assert outcome.result.verdict == expected
    assert "chunk 2/2 [b.js]: not reviewed before the review deadline" in outcome.result.error
    assert rows[1]["verdict"] is None


def test_seat_with_nothing_in_scope_passes_without_a_call_as_today(planner, tmp_path):
    diff = "".join(added(f"web/m{i}.js", filler(60)) for i in range(4))
    plan = chunked.load_plan(write_plan(planner, tmp_path, diff), diff)
    model = FakeBedrock()
    result = chunked.review_panel_chunked(plan, RS, client=model, workers=2, emit=lambda line: None)
    accessibility = dict((a.name, o) for a, o in result.panel)[ACCESSIBILITY]
    assert accessibility.result.verdict == Verdict.PASS
    assert result.details[ACCESSIBILITY]["items"] == []
    assert not any("A11Y-001:" in kw["system"][0]["text"] for kw in model.calls)


# --- small deltas keep today's exact path -----------------------------------------

@pytest.mark.parametrize("diff", ["", added("web/app.js", ["ok"])])
def test_one_chunk_or_empty_plan_takes_the_unchanged_single_call_path(
        planner, tmp_path, monkeypatch, load_module, diff):
    cli = load_module("agent/review_cli.py")
    calls = []

    def panel(text, ruleset, **kw):
        calls.append(text)
        return [(a, ReviewOutcome(GateResult(Verdict.PASS, (), 0), "fake", 0)) for a in ruleset.agents]

    monkeypatch.setattr(cli, "review_panel", panel)
    monkeypatch.setattr(cli, "review_panel_chunked",
                        lambda *a, **k: pytest.fail("chunked path used for a one-chunk delta"))
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff, 100_000), cli=cli)
    assert (code, calls) == (0, [diff])
    assert set(report) == {"verdict", "stats", "findings", "agents"}


# --- the pipeline wiring ------------------------------------------------------------

def _stack_constants():
    tree = ast.parse((ROOT / "tier1-codebuild/tier1_stack.py").read_text())
    nodes = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name)}
    values = {}
    for name in ("REVIEW_TIMEOUT_MINUTES", "REVIEW_WORKERS", "THREAT_TIMEOUT_MINUTES",
                 "STRIDE_WORKERS", "REVIEW_DEADLINE_SECONDS", "STRIDE_DEADLINE_SECONDS"):
        values[name] = eval(compile(ast.Expression(nodes[name]), name, "eval"),  # noqa: S307
                            {"__builtins__": {}}, dict(values))
    return values


def _build_commands(spec_name):
    tree = ast.parse((ROOT / "tier1-codebuild/tier1_stack.py").read_text())
    node = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == spec_name for t in n.targets))
    build = next(v for k, v in zip(node.args[0].keys, node.args[0].values)
                 if ast.literal_eval(k) == "phases")
    build = next(v for k, v in zip(build.keys, build.values) if ast.literal_eval(k) == "build")
    commands = next(v for k, v in zip(build.keys, build.values) if ast.literal_eval(k) == "commands")
    return ast.literal_eval(commands.right)


def test_review_and_threat_actions_consume_the_plan_inside_their_timeouts():
    from reviewer.bedrock_reviewer import READ_TIMEOUT_SECONDS
    c = _stack_constants()
    # The review deadline outlasts one reviewer call at the full read timeout.
    assert c["REVIEW_DEADLINE_SECONDS"] >= READ_TIMEOUT_SECONDS + 5 * 60
    assert c["REVIEW_TIMEOUT_MINUTES"] * 60 - c["REVIEW_DEADLINE_SECONDS"] >= 5 * 60
    assert c["THREAT_TIMEOUT_MINUTES"] * 60 - c["STRIDE_DEADLINE_SECONDS"] >= 5 * 60
    assert c["REVIEW_TIMEOUT_MINUTES"] <= 36 * 60   # CodeBuild and CodePipeline ceiling
    review = next(cmd for cmd in _build_commands("REVIEW_BUILD_SPEC") if "review_cli.py" in cmd)
    stride = next(cmd for cmd in _build_commands("THREAT_BUILD_SPEC") if "stride_agent.py" in cmd)
    for command, prefix in ((review, "REVIEW"), (stride, "STRIDE")):
        assert "--chunk-plan /tmp/review-input/chunk-plan.json" in command
        assert f"--workers ${prefix}_WORKERS" in command
        assert f"--deadline-seconds ${prefix}_DEADLINE_SECONDS" in command
    source = (ROOT / "tier1-codebuild/tier1_stack.py").read_text()
    for name in ("REVIEW_WORKERS", "REVIEW_DEADLINE_SECONDS", "STRIDE_WORKERS",
                 "STRIDE_DEADLINE_SECONDS"):
        assert f'"{name}": codebuild.BuildEnvironmentVariable' in source
    assert "timeout=cdk.Duration.minutes(REVIEW_TIMEOUT_MINUTES)" in source
    assert "timeout=cdk.Duration.minutes(THREAT_TIMEOUT_MINUTES)" in source
    # prepare_review writes the plan where both actions read it.
    prepare = (ROOT / "pipeline_tools/prepare_review.py").read_text()
    assert 'p.add_argument("--output", default="/tmp/review-input")' in prepare


def test_the_buildspec_review_command_parses_with_the_cli(planner, tmp_path, monkeypatch,
                                                         load_module, fake):
    c = _stack_constants()
    review = next(cmd for cmd in _build_commands("REVIEW_BUILD_SPEC") if "review_cli.py" in cmd)
    argv = shlex.split(review.split("python ", 1)[1].split(" || ")[0])
    flags = [a for a in argv if a.startswith("--")]
    assert flags == ["--diff", "--rules", "--region", "--chunk-plan", "--workers",
                     "--deadline-seconds", "--report"]
    diff = site()
    code, report = run_cli(load_module, monkeypatch, tmp_path, diff,
                           write_plan(planner, tmp_path, diff), "--workers",
                           str(c["REVIEW_WORKERS"]), "--deadline-seconds",
                           str(c["REVIEW_DEADLINE_SECONDS"]))
    assert (code, report["verdict"]) == (0, "PASS")
    assert report["chunking"]["workers"] == c["REVIEW_WORKERS"]


# --- the advisory STRIDE lane -------------------------------------------------------

class StrideModel:
    def __init__(self, fail_on=None, hang=None):
        self.users, self.fail_on, self.hang = [], fail_on, hang
        self.release = threading.Event()

    def converse(self, **kw):
        user = kw["messages"][0]["content"][0]["text"]
        self.users.append(user)
        if self.hang and self.hang in user:
            self.release.wait(30)
        if self.fail_on and self.fail_on in user:
            raise RuntimeError("model unavailable")
        return response(json.dumps({"proposed_threats": [{"stride": "Tampering", "statement": "s",
                                                          "boundary": None, "mitigation_hint": "h"}],
                                    "rationale": "r"}))


def run_stride(load_module, monkeypatch, tmp_path, diff, model, *extra):
    stride = load_module("threat-model/stride_agent.py")
    monkeypatch.setattr(stride.boto3, "client", lambda *a, **k: model)
    (tmp_path / "change.diff").write_text(diff)
    report = tmp_path / "stride.json"
    monkeypatch.setattr(sys, "argv", ["stride", "--diff", str(tmp_path / "change.diff"),
                                      "--model-file", str(ROOT / "threat-model/app.tc.json"),
                                      "--report", str(report), *extra])
    assert stride.main() == 0
    return json.loads(report.read_text())


def test_stride_proposes_per_chunk_and_stays_advisory(planner, tmp_path, monkeypatch, load_module):
    diff = site()
    plan_path = write_plan(planner, tmp_path, diff)
    chunks = len(json.loads(plan_path.read_text())["chunks"])
    model = StrideModel(fail_on="diff --git a/web/m3.js")
    report = run_stride(load_module, monkeypatch, tmp_path, diff, model,
                        "--chunk-plan", str(plan_path), "--workers", "3", "--deadline-seconds", "30")
    assert len(report["chunks"]) == len(model.users) == chunks
    assert report["error"].startswith("1 of")
    failed = next(r["index"] for r in report["chunks"] if r["error"])
    assert len(report["proposed_threats"]) == chunks - 1
    assert failed not in {t["chunk"] for t in report["proposed_threats"]}


def test_stride_deadline_is_advisory_and_prompt(planner, tmp_path, monkeypatch, load_module):
    diff = site()
    model = StrideModel(hang="diff --git a/web/m1.js")
    started = time.monotonic()
    report = run_stride(load_module, monkeypatch, tmp_path, diff, model, "--chunk-plan",
                        str(write_plan(planner, tmp_path, diff)), "--deadline-seconds", "1")
    model.release.set()
    assert time.monotonic() - started < 10
    assert "not reviewed before the deadline" in report["error"]


def test_stride_reads_all_text_after_reasoning_and_sends_no_temperature(load_module):
    stride = load_module("threat-model/stride_agent.py")
    seen = []

    class Thinking:
        def __init__(self, stop):
            self.stop = stop

        def converse(self, **kw):
            seen.append(kw)
            return {"output": {"message": {"content": [
                {"reasoningContent": {"reasoningText": {"text": "considering STRIDE"}}},
                {"text": '{"proposed_threats": [{"stride": "Tampering", '},
                {"text": '"statement": "s", "boundary": null, "mitigation_hint": "h"}], '
                         '"rationale": "r"}'}]}}, "stopReason": self.stop}

    threats, rationale = stride._propose(Thinking("end_turn"), "m", "{}", "diff")
    assert [t["stride"] for t in threats] == ["Tampering"] and rationale == "r"
    assert "temperature" not in seen[0]["inferenceConfig"]
    with pytest.raises(ValueError, match="stopReason=max_tokens"):
        stride._propose(Thinking("max_tokens"), "m", "{}", "diff")


def test_stride_single_chunk_is_one_call_over_the_whole_diff(planner, tmp_path, monkeypatch,
                                                             load_module):
    diff = added("template.yaml", ["Resources: {}"])
    model = StrideModel()
    report = run_stride(load_module, monkeypatch, tmp_path, diff, model, "--chunk-plan",
                        str(write_plan(planner, tmp_path, diff, 100_000)))
    assert len(model.users) == 1 and diff in model.users[0]
    assert set(report) == {"advisory", "proposed_threats", "rationale", "error"}


def test_git_header_regex_does_not_backtrack_exponentially():
    # [^"] also matched a backslash, so '"\!\!...' could split 2^n ways (CodeQL py/redos):
    # n=26 took 5-9 seconds before the fix. One prefix per quoted group.
    for prefix in ('"', '"" "'):
        start = time.monotonic()
        assert chunked._GIT_HEADER.fullmatch(prefix + '\\!' * 26) is None
        assert time.monotonic() - start < 1, prefix
    quoted = r'"a/sp\"ace \\x" "b/sp\"ace \\x"'
    assert chunked._GIT_HEADER.fullmatch(quoted).group(2) == r'"b/sp\"ace \\x"'
