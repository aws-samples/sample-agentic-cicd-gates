"""Publisher identity, complete PR reports, and current-vs-history regressions."""
import copy
import unittest
from unittest.mock import patch

import test_evidence as fixtures
from test_evidence import h, SHA, OTHER, published_review
from evidence import agent_review_history

PERSONA = "Security Review Agent"
LONG_MESSAGE = ("Full retained explanation, including the boundary and suggested remediation. " * 30).strip()


def finding(message=LONG_MESSAGE, code=""):
    return ("\n### Finding\n\n**SEC-003** — high, blocking, confidence 99\n\n"
            f"src/handler.py:37\n\n{message}" +
            ("\n\nSuggested code (review before applying):\n\n" + code if code else "") + "\n")


def failed(review_id=1, head=SHA, run=50, attempt=1, total=1):
    rv = published_review(review_id, head, "FAIL", run, attempt)
    rv["state"] = "CHANGES_REQUESTED"
    rv["body"] = rv["body"].replace("| 0 | 0 |", f"| {total} | {total} |") + finding()
    return rv


def continuation(primary, review_id, part, message=LONG_MESSAGE):
    rv = copy.deepcopy(primary)
    rv.update(id=review_id, state="COMMENTED")
    marker = rv["body"].split("\n", 1)[0].replace("part=1", f"part={part}")
    rv["body"] = marker + f"\n## {PERSONA} — continued findings\n\n" + finding(message)
    rv["html_url"] += f"-part-{part}"
    return rv


class ReviewHistoryTests(unittest.TestCase):
    setUp = fixtures.EvidenceTests.setUp

    def history(self, reviews, comments=()):
        return agent_review_history(reviews, comments, "test/r", 7, h.PERSONAS)

    def surface(self, reviews, head=SHA, run=50, attempt=1, comments=(), queued=False, feed=None):
        pr = {"number": 7, "title": "fixture", "head": {"sha": head},
              "html_url": "https://github.com/test/r/pull/7", "state": "closed",
              "merged_at": "2026-08-18T00:04:00Z", "updated_at": "2026-08-18T00:04:00Z"}
        def read(path, *args, **kwargs):
            if "/pulls?" in path:
                return [pr]
            if "/actions/runs?" in path:
                return {"workflow_runs": [{"id": run, "workflow_id": 5, "run_attempt": attempt,
                        "event": "pull_request", "head_sha": head, "name": "Agentic review",
                        "status": "queued" if queued else "completed"}]}
            if "/jobs?" in path:
                return {"jobs": []}
            if "/reviews?" in path:
                return reviews
            if "/comments?" in path:
                return list(comments)
            raise AssertionError(path)
        with patch.object(h, "_gh", side_effect=read):
            result = h._pr_surface(feed if feed is not None else [], 7, "test/r", True)
        self.assertEqual(result["evidence"]["state"], "available", result)
        return result["detail"]

    def test_dismissed_failure_survives_later_head_pass_with_full_reason(self):
        old = failed(head=OTHER, run=49)
        old["state"] = "DISMISSED"
        latest = published_review(2, SHA)
        detail = self.surface([old, latest])
        self.assertEqual([r["id"] for r in detail["reviews"]], [2])
        previous = next(r for r in detail["history"] if r["id"] == 1)
        self.assertEqual(previous["verdict"], "FAIL")
        self.assertEqual(previous["state"], "DISMISSED")
        self.assertFalse(previous["is_current"])
        self.assertEqual(previous["findings"][0]["message"], LONG_MESSAGE)
        self.assertEqual(previous["report_body"], old["body"])
        self.assertEqual(detail["findings"], [])

    def test_same_head_new_attempt_pass_does_not_remove_failed_attempt(self):
        old = failed(attempt=1)
        latest = published_review(2, SHA, attempt=2)
        detail = self.surface([old, latest], attempt=2)
        self.assertEqual([(r["id"], r["verdict"]) for r in detail["reviews"]], [(2, "PASS")])
        self.assertFalse(next(r for r in detail["history"] if r["id"] == 1)["is_current"])

    def test_same_head_new_run_failure_does_not_reuse_old_pass(self):
        old = published_review(1, SHA, run=49)
        latest = failed(2, run=50)
        detail = self.surface([old, latest])
        self.assertEqual([r["verdict"] for r in detail["reviews"]], ["FAIL"])
        self.assertEqual(len(detail["history"]), 2)

    def test_queued_same_head_retry_keeps_old_pass_only_in_history(self):
        detail = self.surface([published_review(1, SHA, attempt=1)], attempt=2, queued=True)
        self.assertEqual(detail["reviews"], [])
        self.assertTrue(detail["review_running"])
        self.assertFalse(detail["history"][0]["is_current"])

    def test_parts_are_joined_numerically_without_losing_continuation(self):
        first = failed(total=3)
        second = continuation(first, 2, 2, "Second complete finding")
        third = continuation(first, 3, 3, "Third complete finding")
        [report] = self.history([third, first, second])
        self.assertEqual(report["id"], 1)
        self.assertEqual(report["review_ids"], [1, 2, 3])
        self.assertEqual(report["report_body"], "\n\n".join(r["body"] for r in [first, second, third]))
        self.assertEqual([f["message"] for f in report["findings"]],
                         [LONG_MESSAGE, "Second complete finding", "Third complete finding"])
        self.assertNotIn("error", report)

    def test_missing_tail_or_gap_never_establishes_clean_pass(self):
        first = published_review(1, SHA)
        first["body"] = first["body"].replace("| 0 | 0 |", "| 0 | 2 |")
        for reviews in ([first], [first, continuation(first, 3, 3)]):
            [report] = self.history(reviews)
            self.assertEqual(report["verdict"], "UNAVAILABLE")
            self.assertEqual(report["evidence"]["state"], "unavailable")
            self.assertIn("error", report)

    def test_duplicate_parts_are_flagged_and_all_bodies_preserved(self):
        first = failed()
        duplicate = copy.deepcopy(first)
        duplicate["id"] = 2
        duplicate["body"] += "\nExtra published diagnostic"
        [report] = self.history([first, duplicate])
        self.assertIn("duplicate", report["error"])
        self.assertIn("Extra published diagnostic", report["report_body"])
        self.assertEqual(report["review_ids"], [1, 2])

    def test_orphan_continuation_is_retained_as_incomplete_not_pass(self):
        [report] = self.history([continuation(failed(), 2, 2)])
        self.assertEqual(report["verdict"], "UNAVAILABLE")
        self.assertEqual(report["evidence"]["state"], "missing")
        self.assertIn("Primary report counts unavailable", report["error"])
        self.assertEqual(report["findings"][0]["message"], LONG_MESSAGE)

    def test_complete_error_is_retained(self):
        rv = published_review(1, SHA, "BLOCKED_ERROR")
        error = "Model/provider error: " + LONG_MESSAGE
        rv["body"] += "\n**Review incomplete:** " + error + "\n"
        [report] = self.history([rv])
        self.assertEqual(report["error"], error)
        self.assertEqual(report["report_body"], rv["body"])
        self.assertEqual(report["verdict"], "BLOCKED_ERROR")
        self.assertEqual(report["evidence"]["state"], "available")

    def test_incomplete_publication_and_actual_review_error_have_distinct_feed_states(self):
        incomplete = published_review(1, SHA)
        incomplete["body"] = incomplete["body"].replace("| 0 | 0 |", "| 0 | 1 |")
        feed = []
        detail = self.surface([incomplete], feed=feed)
        self.assertEqual(detail["reviews"][0]["verdict"], "UNAVAILABLE")
        self.assertEqual(feed[-1]["status"], "Unavailable")
        error = published_review(2, SHA, "BLOCKED_ERROR")
        error["body"] += "\n**Review incomplete:** Actual provider error\n"
        feed = []
        self.surface([error], feed=feed)
        self.assertEqual(feed[-1]["status"], "Failed")

    def test_human_spoofed_heading_marker_or_wrong_bot_identity_is_not_trusted(self):
        for user in [{"login": "someone", "type": "User", "id": 1},
                     {"login": "github-actions[bot]", "type": "Bot", "id": 1},
                     {"login": "github-actions[bot]", "type": "User", "id": 41898282}, {}]:
            rv = failed()
            rv["user"] = user
            self.assertEqual(self.history([rv]), [])

    def test_mismatched_marker_identities_are_not_trusted(self):
        original = failed()
        for before, after in [("repo=test/r", "repo=other/r"), ("pr=7", "pr=8"),
                              (f"head={SHA}", f"head={OTHER}"),
                              ("reviewer=0cf9b9ba2bed46c3", "reviewer=ffffffffffffffff"),
                              ("## 🛡️ Security Review Agent", "## 🛡️ Architecture Review Agent"),
                              ("/runs/50/attempts/1", "/runs/51/attempts/1")]:
            rv = copy.deepcopy(original)
            rv["body"] = rv["body"].replace(before, after)
            self.assertEqual(self.history([rv]), [], (before, after))
        rv = copy.deepcopy(original)
        rv["body"] = rv["body"].split("\n", 1)[1]
        self.assertEqual(self.history([rv]), [])

    def test_suggested_code_and_embedded_heading_are_not_truncated_or_split(self):
        rv = failed()
        code = "```\n### Finding\n" + "repair line\n" * 100 + "```"
        rv["body"] = rv["body"].split("\n### Finding", 1)[0] + finding(code=code)
        [report] = self.history([rv])
        self.assertEqual(len(report["findings"]), 1)
        self.assertTrue(report["findings"][0]["message"].endswith(code))
        self.assertNotIn("error", report)

    def test_inline_enrichment_requires_bot_head_group_and_persona(self):
        rv = failed()
        comment = {"user": rv["user"], "commit_id": SHA, "pull_request_review_id": 1,
                   "path": "src/handler.py", "line": 37, "position": None,
                   "html_url": "https://github.com/test/inline",
                   "body": f"🛡️ **{PERSONA}** · **SEC-003** (high, blocking, confidence 99)\n\n{LONG_MESSAGE}"}
        [report] = self.history([rv], [comment])
        self.assertEqual(len(report["findings"]), 1)
        self.assertTrue(report["findings"][0]["outdated"])
        self.assertEqual(report["findings"][0]["url"], comment["html_url"])
        self.assertEqual(report["findings"][0]["message"], LONG_MESSAGE)
        for change in [{"user": {"id": 1}}, {"commit_id": OTHER}, {"pull_request_review_id": 999},
                       {"body": comment["body"].replace(PERSONA, "Code Quality Review Agent")}]:
            [report] = self.history([rv], [{**comment, **change}])
            self.assertEqual(report["findings"][0]["url"], rv["html_url"])

    def test_history_read_failure_is_unavailable_not_empty_pass(self):
        with patch.object(h, "_gh_pages", side_effect=RuntimeError("GitHub history unavailable")), \
             patch.object(h, "_gh_read", return_value=[{"number": 7, "title": "fixture",
                 "head": {"sha": SHA}, "html_url": "https://github.com/test/r/pull/7",
                 "state": "open", "updated_at": ""}]):
            result = h._pr_surface([], 7, "test/r")
        self.assertIsNone(result["detail"])
        self.assertEqual(result["evidence"]["state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
