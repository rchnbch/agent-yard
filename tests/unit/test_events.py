import json
import os
import tempfile
import unittest

from yard.events import CursorError, EventLog, parse_cursor


class EventLogTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = EventLog(os.path.join(self.dir.name, "events.jsonl"))

    def tearDown(self):
        self.dir.cleanup()

    def test_empty(self):
        self.assertEqual(self.log.read_since(None), {"events": [], "cursor": "c0", "more": False})

    def test_append_and_cursor(self):
        for i in range(5):
            self.log.append("job.status", "j1", {"i": i})
        first = self.log.read_since(None, limit=2)
        self.assertEqual([e["seq"] for e in first["events"]], [1, 2])
        self.assertTrue(first["more"])
        rest = self.log.read_since(first["cursor"])
        self.assertEqual([e["data"]["i"] for e in rest["events"]], [2, 3, 4])
        self.assertEqual(rest["cursor"], "c5")
        self.assertEqual(self.log.read_since(rest["cursor"])["events"], [])
        self.assertEqual(self.log.read_since(rest["cursor"])["cursor"], "c5")

    def test_survives_reopen_and_torn_line(self):
        self.log.append("job.created", "j1")
        with open(self.log.path, "ab") as fh:
            fh.write(b'{"seq": 2, "type": "job.st')  # crash mid-write
        ev = EventLog(self.log.path).append("job.running", "j1")
        self.assertEqual(ev["seq"], 2)
        types = [e["type"] for e in self.log.read_since(None)["events"]]
        self.assertEqual(types, ["job.created", "job.running"])

    def test_job_filter_keeps_cursor_moving(self):
        self.log.append("job.created", "a")
        self.log.append("job.created", "b")
        res = self.log.read_since(None, job="b")
        self.assertEqual([e["job"] for e in res["events"]], ["b"])
        self.assertEqual(res["cursor"], "c2")

    def test_rejects_unknown_type_and_bad_cursor(self):
        with self.assertRaises(ValueError):
            self.log.append("job.exploded")
        for bad in ("5", "cx", "c-1", 7):
            with self.subTest(bad=bad), self.assertRaises(CursorError):
                parse_cursor(bad)

    def test_lines_are_json(self):
        self.log.append("job.status", "j", {"note": "line\nbreak \"quoted\""})
        with open(self.log.path) as fh:
            lines = fh.read().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["data"]["note"], "line\nbreak \"quoted\"")
