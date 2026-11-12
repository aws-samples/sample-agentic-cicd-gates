import hashlib
import importlib.util
import json
import pathlib
import re
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "review_chunks", pathlib.Path(__file__).with_name("review_chunks.py"))
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

LIMIT = 6_000
HUNK = re.compile(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@")


def header(path, new=True):
    extra = "new file mode 100644\nindex 0000000..1111111\n--- /dev/null\n" if new else \
        "index 1111111..2222222 100644\n--- a/" + path + "\n"
    return f"diff --git a/{path} b/{path}\n{extra}+++ b/{path}\n"


def added(path, lines):
    body = "".join(f"+{line}\n" for line in lines)
    return header(path) + f"@@ -0,0 +1,{len(lines)} @@\n" + body


def code(n, width=50, stem="x"):
    """n lines of plausible code with a top-level declaration every 12 lines."""
    out = []
    for i in range(n):
        if i % 12 == 0:
            out.append("")
            out.append(f"function {stem}{i}(a, b) {{")
        out.append(f"  const v{i} = a * {i} + b; // {'.' * (width - 30)}")
        if i % 12 == 11:
            out.append("}")
    return out


def rebuild(chunks):
    """Original diff from a plan: first piece keeps its header, later ones drop it."""
    units = sorted((u for c in chunks for u in c.units), key=lambda u: (u.seq, u.part))
    return "".join(u.text if u.part == 1 else u.body for u in units)


def subhunks(chunks, path):
    pieces = sorted((u for c in chunks for u in c.units if u.path == path), key=lambda u: u.part)
    out = []
    for piece in pieces:
        for line in rc.split_lines(piece.body):
            if line.startswith("@@ "):
                out.append([line])
            else:
                out[-1].append(line)
    return out


class PlanTests(unittest.TestCase):
    def test_small_diff_is_one_chunk_equal_to_the_diff(self):
        diff = added("app.py", ["print('hi')"]) + added("web/index.html", ["<p>hi</p>"])
        chunks = rc.plan(diff, LIMIT)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].text, diff)

    def test_empty_diff_has_no_chunks(self):
        self.assertEqual(rc.plan("", LIMIT), [])

    def test_whole_files_pack_in_diff_order_and_cover_everything(self):
        files = [added(f"src/f{i:02d}.js", code(5 + 7 * (i % 9))) for i in range(30)]
        diff = "".join(files)
        chunks = rc.plan(diff, LIMIT)
        self.assertGreater(len(chunks), 3)
        for chunk in chunks:
            self.assertLessEqual(rc.nbytes(chunk.text), LIMIT)
            seqs = [u.seq for u in chunk.units]
            self.assertEqual(seqs, sorted(seqs))
            self.assertTrue(all(u.parts == 1 for u in chunk.units))
        self.assertEqual(rebuild(chunks), diff)
        self.assertEqual(sorted(u.seq for c in chunks for u in c.units), list(range(30)))

    def test_first_fit_fills_earlier_chunks(self):
        big, small = code(80), code(3)
        diff = "".join(added(f"f{i}.js", big if i % 2 == 0 else small) for i in range(6))
        chunks = rc.plan(diff, LIMIT)
        # Small files back-fill the room left beside big ones.
        self.assertLess(len(chunks), 6)

    def test_multi_hunk_file_splits_into_whole_hunks(self):
        old = [f"line {i}" for i in range(2000)]
        new = list(old)
        hunks = []
        for start in range(10, 1900, 160):
            new[start] = f"changed {start}"
            ctx = range(start - 3, start + 4)
            body = ""
            for j in ctx:
                body += f"-{old[j]}\n+{new[j]}\n" if j == start else f" {old[j]}\n"
            body = body + " pad " + "." * 400 + "\n"  # fat hunks, still well under LIMIT
            hunks.append(f"@@ -{start - 2},8 +{start - 2},8 @@\n" + body)
        section = header("big.txt", new=False) + "".join(hunks)
        chunks = rc.plan(section, LIMIT)
        pieces = [u for c in chunks for u in c.units]
        self.assertGreater(len(pieces), 1)
        self.assertTrue(all(u.text.startswith(header("big.txt", new=False)) for u in pieces))
        # Whole hunks: every original hunk header survives unchanged.
        got = [line for u in pieces for line in rc.split_lines(u.body) if line.startswith("@@ ")]
        self.assertEqual(sorted(got), sorted(h.split("\n", 1)[0] + "\n" for h in hunks))
        self.assertEqual(rebuild(chunks), section)

    def test_one_huge_added_file_splits_at_lines_with_correct_numbers(self):
        lines = code(400)
        diff = added("src/kit/figures.js", lines)
        self.assertGreater(rc.nbytes(diff), 2 * LIMIT)
        chunks = rc.plan(diff, LIMIT)
        parts = sorted((u for c in chunks for u in c.units), key=lambda u: u.part)
        self.assertGreater(len(parts), 2)
        self.assertTrue(all(rc.nbytes(c.text) <= LIMIT for c in chunks))
        expected_start = 1
        content = []
        for hunk in subhunks(chunks, "src/kit/figures.js"):
            m = HUNK.match(hunk[0])
            self.assertEqual((m[1], m[2]), ("0", "0"))
            self.assertEqual(int(m[3]), expected_start)
            self.assertEqual(int(m[4]), len(hunk) - 1)
            expected_start += len(hunk) - 1
            content += [line[1:-1] for line in hunk[1:]]
        self.assertEqual(content, lines)
        self.assertEqual(rc.strip_hunk_headers(rebuild(chunks)), rc.strip_hunk_headers(diff))

    def test_split_modified_hunk_numbers_both_sides_exactly(self):
        old = [f"old {i} " + "o" * 40 for i in range(1, 801)]
        body, new = [], []
        for i, line in enumerate(old):
            if i % 7 == 3:
                body.append(f"-{line}\n")
            elif i % 11 == 5:
                body += [f" {line}\n", f"+inserted after {i} " + "n" * 30 + "\n"]
                new += [line, f"inserted after {i} " + "n" * 30]
            else:
                body.append(f" {line}\n")
                new.append(line)
        diff = header("mod.js", new=False) + f"@@ -1,{len(old)} +1,{len(new)} @@ intro\n" + "".join(body)
        chunks = rc.plan(diff, LIMIT)
        hunks = subhunks(chunks, "mod.js")
        self.assertGreater(len(hunks), 2)
        for hunk in hunks:
            m = HUNK.match(hunk[0])
            self.assertTrue(hunk[0].endswith(" @@ intro\n"))
            o, oc, n, nc = (int(x) for x in m.groups())
            olds = [line[1:-1] for line in hunk[1:] if line[0] in " -"]
            news = [line[1:-1] for line in hunk[1:] if line[0] in " +"]
            self.assertEqual((len(olds), len(news)), (oc, nc))
            if oc:
                self.assertEqual(old[o - 1:o - 1 + oc], olds)
            if nc:
                self.assertEqual(new[n - 1:n - 1 + nc], news)

    def test_no_newline_marker_never_starts_a_piece(self):
        lines = [f"+value {i} " + "v" * 60 + "\n" for i in range(300)]
        lines[150] = lines[150] + "\\ No newline at end of file\n"
        diff = header("n.txt") + "@@ -0,0 +1,300 @@\n" + "".join(lines)
        for chunk in rc.plan(diff, LIMIT):
            for unit in chunk.units:
                body = rc.split_lines(unit.body)
                self.assertFalse(body[1].startswith("\\"))

    def test_cut_prefers_a_gap_between_declarations(self):
        chunks = rc.plan(added("decl.js", code(300)), LIMIT)
        for hunk in subhunks(chunks, "decl.js")[1:]:
            first = hunk[1]
            self.assertTrue(first == "+\n" or first.startswith("+function"), first)

    def test_line_larger_than_a_chunk_fails_closed(self):
        diff = added("min.js", ["x" * (2 * LIMIT)])
        with self.assertRaises(rc.PlanError):
            rc.plan(diff, LIMIT)

    def test_unicode_line_separators_are_content_not_boundaries(self):
        tricky = "a\x0cdiff --git a/x.png b/x.png @@ -1 +1 @@\x85\rtail"
        diff = added("web/page.html", [tricky] * 3) + added("b.py", ["ok"])
        sections = rc.parse_sections(diff)
        self.assertEqual([s.path for s in sections], ["web/page.html", "b.py"])
        self.assertEqual(rebuild(rc.plan(diff, LIMIT)), diff)

    def test_binary_rename_and_mode_sections_are_whole_units(self):
        diff = ("diff --git a/logo.png b/logo.png\nnew file mode 100644\nindex 0000000..e69de29\n"
                "Binary files /dev/null and b/logo.png differ\n"
                "diff --git a/old.py b/new.py\nsimilarity index 100%\nrename from old.py\nrename to new.py\n"
                "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n"
                + added('"sp ace.js"'.strip('"'), ["1"]))
        chunks = rc.plan(diff, LIMIT)
        self.assertEqual([u.path for u in chunks[0].units], ["logo.png", "new.py", "run.sh", "sp ace.js"])
        self.assertEqual(chunks[0].text, diff)

    def test_text_before_first_header_is_refused(self):
        with self.assertRaises(rc.PlanError):
            rc.plan("garbage\n" + added("a.py", ["1"]), LIMIT)

    def test_verify_rejects_lost_or_repeated_content(self):
        diff = "".join(added(f"f{i}.js", code(40)) for i in range(6))
        chunks = rc.plan(diff, LIMIT)
        dropped = [rc.Chunk(c.index, c.units[1:] if c.index == 1 and len(c.units) > 1 else c.units)
                   for c in chunks]
        if dropped != chunks:
            with self.assertRaises(rc.PlanError):
                rc.verify(diff, dropped, LIMIT)
        unit = chunks[0].units[0]
        tampered = rc.Unit(unit.seq, unit.path, 1, 1, unit.header,
                           unit.body.replace("const v", "const w", 1))
        with self.assertRaises(rc.PlanError):
            rc.verify(diff, [rc.Chunk(0, (tampered,) + chunks[0].units[1:])] + chunks[1:], LIMIT)
        with self.assertRaises(rc.PlanError):
            rc.verify(diff, chunks + [rc.Chunk(len(chunks), (unit,))], 10 * LIMIT)

    def test_chunk_size_floor(self):
        with self.assertRaises(rc.PlanError):
            rc.plan(added("a.py", ["1"]), 100)

    def test_write_plan_records_every_chunk_and_digest(self):
        diff = "".join(added(f"f{i}.js", code(60)) for i in range(5)) + added("big.js", code(300))
        chunks = rc.plan(diff, LIMIT)
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            summary = rc.write_plan(chunks, diff, LIMIT, out)
            raw = (out / rc.PLAN_FILE).read_bytes()
            doc = json.loads(raw)
            self.assertEqual(summary["plan_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(summary["chunks"], len(chunks))
            self.assertEqual(summary["split_files"], ["big.js"])
            self.assertEqual(doc["diff_sha256"], hashlib.sha256(diff.encode()).hexdigest())
            self.assertEqual(doc["files"], 6)
            for row, chunk in zip(doc["chunks"], chunks):
                data = (out / row["path"]).read_bytes()
                self.assertEqual(data, chunk.text.encode())
                self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(sum(u["bytes"] for u in row["units"]), len(data))


if __name__ == "__main__":
    unittest.main()
