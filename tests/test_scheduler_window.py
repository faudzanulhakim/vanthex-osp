"""Hermetic tests for scheduler windows + auto-diff (v1.2.3).

AUTHORIZED TESTING ONLY.

No network, no running server: window matching / catchup are pure store
functions; diff_mode uses a real store layer pointed at a throwaway temp
SQLite DB (in-memory equivalent).
"""
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import store  # noqa: E402


def _ts(**kw):
    """Timestamp from an explicit local datetime (TZ-independent tests)."""
    return datetime(**kw).timestamp()


def _local(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi).timestamp()


class TestParseScheduleWindow(unittest.TestCase):
    def test_valid_window_normalized(self):
        w = store.parse_schedule_window(
            {"days": [1, 3, 3, 0], "start": "02:00", "end": "04:30"})
        self.assertEqual(w, {"days": [0, 1, 3], "start": "02:00", "end": "04:30"})

    def test_days_default_all(self):
        w = store.parse_schedule_window({"start": "09:00", "end": "17:00"})
        self.assertEqual(w["days"], [0, 1, 2, 3, 4, 5, 6])

    def test_invalid_rejected(self):
        for raw in (None, {}, {"start": "02:00"},
                    {"start": "25:00", "end": "03:00"},
                    {"start": "02:00", "end": "2:5"},
                    {"start": "02:00", "end": "03:00", "days": [7]},
                    {"start": "02:00", "end": "03:00", "days": "mon"},
                    {"start": "02:00", "end": "03:00", "days": []},
                    "02:00-03:00"):
            self.assertIsNone(store.parse_schedule_window(raw))


class TestWindowMatching(unittest.TestCase):
    W = {"days": [0], "start": "02:00", "end": "03:00"}  # Monday 02-03

    def test_inside_window(self):
        # Pick a date that is actually a Monday.
        dt = datetime(2026, 11, 2)  # Monday
        self.assertEqual(dt.weekday(), 0)
        self.assertTrue(store._in_window(store.parse_schedule_window(self.W),
                                         dt.replace(hour=2, minute=0).timestamp()))
        self.assertTrue(store._in_window(store.parse_schedule_window(self.W),
                                         dt.replace(hour=2, minute=59).timestamp()))

    def test_boundary_start_inclusive_end_exclusive(self):
        w = store.parse_schedule_window(self.W)
        mon = datetime(2026, 11, 2)
        self.assertTrue(store._in_window(w, mon.replace(hour=2, minute=0).timestamp()))     # start in
        self.assertFalse(store._in_window(w, mon.replace(hour=3, minute=0).timestamp()))    # end out
        self.assertFalse(store._in_window(w, mon.replace(hour=1, minute=59).timestamp()))   # just before

    def test_wrong_day_out(self):
        w = store.parse_schedule_window(self.W)
        tue = datetime(2026, 11, 3).replace(hour=2, minute=30)  # Tuesday
        self.assertEqual(tue.weekday(), 1)
        self.assertFalse(store._in_window(w, tue.timestamp()))

    def test_overnight_window(self):
        # Friday 22:00 -> Saturday 02:00; window day key is the day it starts.
        w = store.parse_schedule_window(
            {"days": [4], "start": "22:00", "end": "02:00"})
        fri_late = datetime(2026, 11, 6, 22, 30)  # Friday 22:30
        self.assertEqual(datetime(2026, 11, 6).weekday(), 4)
        self.assertTrue(store._in_window(w, fri_late.timestamp()))
        sat_early = datetime(2026, 11, 7, 1, 30)  # Saturday 01:30, after midnight
        self.assertTrue(store._in_window(w, sat_early.timestamp()))
        mid = datetime(2026, 11, 6, 12, 0)
        self.assertFalse(store._in_window(w, mid.timestamp()))


class TestWindowFire(unittest.TestCase):
    # Monday 2026-11-02, window 02:00-03:00
    WIN = {"days": [0], "start": "02:00", "end": "03:00"}

    def test_no_window_always_fires(self):
        now = _local(2026, 11, 3, 9, 0)
        for win in (None, "", "junk", {}):
            self.assertEqual(store.window_fire(win, now - 100, now), (True, False))

    def test_fires_inside_window(self):
        now = _local(2026, 11, 2, 2, 30)
        self.assertEqual(store.window_fire(self.WIN, now - 3600, now), (True, False))

    def test_waits_before_window(self):
        # due since Friday, window not yet reached (Sunday 20:00)
        now = _local(2026, 11, 1, 20, 0)
        self.assertEqual(store.window_fire(self.WIN, now - 3600, now), (False, False))

    def test_catchup_after_missed_window(self):
        # Window Mon 02:00-03:00 fully passed while due; now Mon 10:00.
        now = _local(2026, 11, 2, 10, 0)
        next_run = now - 8 * 3600  # was due before the window
        fire, catchup = store.window_fire(self.WIN, next_run, now)
        self.assertTrue(fire)
        self.assertTrue(catchup)

    def test_catchup_not_before_window_elapsed(self):
        # Due at 02:30 (inside window) but... still inside window -> normal.
        now = _local(2026, 11, 2, 2, 10)
        self.assertEqual(store.window_fire(self.WIN, now - 60, now)[1], False)

    def test_no_catchup_if_window_after_next_run_future(self):
        # Window passed BEFORE the schedule became due -> no catchup.
        now = _local(2026, 11, 2, 10, 0)
        next_run = _local(2026, 11, 2, 9, 0)  # became due after window ended
        self.assertEqual(store.window_fire(self.WIN, next_run, now), (False, False))

    def test_catchup_days_later_fires_once(self):
        # Server down over the Monday window, back Thursday: catchup once.
        now = _local(2026, 11, 5, 8, 0)
        next_run = _local(2026, 11, 1, 12, 0)
        fire, catchup = store.window_fire(self.WIN, next_run, now)
        self.assertEqual((fire, catchup), (True, True))


class TestDiffModeSummary(unittest.TestCase):
    def setUp(self):
        self._old = store.DB_PATH
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        store.DB_PATH = self.tmp.name
        store.init_db()
        store.init_v32()

    def tearDown(self):
        store.DB_PATH = self._old
        os.unlink(self.tmp.name)

    def _scan(self, findings):
        return store.save_scan("t.local", "vulnscan", "passive-full",
                               {"overall_risk": "M", "summary": {},
                                "findings": findings})

    def test_first_scan_all_new(self):
        sid = self._scan([{"title": "A", "severity": "high"},
                          {"title": "B", "severity": "low"}])
        s = store.scan_diff_summary(sid)
        self.assertEqual(s["new"], 2)
        self.assertEqual(s["resolved"], 0)
        self.assertEqual(s["by_severity"], {"high": 1, "low": 1})

    def test_second_scan_new_and_resolved(self):
        self._scan([{"title": "A", "severity": "high"},
                    {"title": "B", "severity": "low"}])
        s1 = self._scan([{"title": "A", "severity": "high"},
                         {"title": "C", "severity": "medium"}])
        s = store.scan_diff_summary(s1)
        self.assertEqual(s["new"], 1)       # C is new
        self.assertEqual(s["resolved"], 1)  # B resolved
        self.assertEqual(s["by_severity"], {"medium": 1})

    def test_bounded_titles(self):
        many = [{"title": f"F{i}", "severity": "info"} for i in range(30)]
        sid = self._scan(many)
        s = store.scan_diff_summary(sid)
        self.assertEqual(s["new"], 30)
        self.assertLessEqual(len(s["new_titles"]), 20)

    def test_schema_backward_compat(self):
        # Old-style schedule (no window / no diff_mode) still round-trips
        # and window_fire treats it as always-fire.
        sid = store.create_schedule("old.local", "passive-full", 24, "tester")
        rows = [r for r in store.list_schedules() if r["id"] == sid]
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["window"])
        self.assertFalse(rows[0]["diff_mode"])
        self.assertEqual(store.window_fire(rows[0]["window"],
                                           rows[0]["next_run"] - 10),
                         (True, False))

    def test_new_fields_round_trip(self):
        sid = store.create_schedule("new.local", "passive-full", 24, "tester",
                                    window={"days": [0, 1], "start": "02:00",
                                            "end": "04:00"},
                                    diff_mode=True)
        row = [r for r in store.list_schedules() if r["id"] == sid][0]
        self.assertEqual(row["window"],
                         {"days": [0, 1], "start": "02:00", "end": "04:00"})
        self.assertTrue(row["diff_mode"])


if __name__ == "__main__":
    unittest.main()
