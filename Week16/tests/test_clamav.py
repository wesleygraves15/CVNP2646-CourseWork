"""Tests for ClamAV-specific checks — signature freshness and scheduled tasks."""

import time
import unittest
from unittest.mock import patch

import endpoint_check as ec


def fake_run(stdout="", rc=0):
    return (stdout, rc)


class TestSignatureFreshness(unittest.TestCase):

    def test_recent_passes(self):
        spec = {
            "paths": ["/var/lib/clamav/daily.cvd"],
            "max_age_days": 7,
        }
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value.st_mtime = time.time() - 3600  # 1 hour ago
            status, _ = ec.check_signature_freshness(spec)
        self.assertEqual(status, "pass")

    def test_stale_warns(self):
        spec = {
            "paths": ["/var/lib/clamav/daily.cvd"],
            "max_age_days": 7,
        }
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value.st_mtime = time.time() - (30 * 86400)  # 30d
            status, detail = ec.check_signature_freshness(spec)
        self.assertEqual(status, "warn")
        self.assertIn("30", detail)

    def test_missing_db_fails(self):
        spec = {"paths": ["/missing.cvd"], "max_age_days": 7}
        with patch("pathlib.Path.is_file", return_value=False):
            status, _ = ec.check_signature_freshness(spec)
        self.assertEqual(status, "fail")

    def test_default_max_age_is_seven_days(self):
        spec = {"paths": ["/var/lib/clamav/daily.cvd"]}  # max_age_days omitted
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value.st_mtime = time.time() - (10 * 86400)
            status, _ = ec.check_signature_freshness(spec)
        self.assertEqual(status, "warn")  # 10d > 7d default


class TestScheduledTask(unittest.TestCase):

    def test_systemd_timer_passes(self):
        spec = {"timer_pattern": "clam", "cron_pattern": "clamscan"}

        def side_effect(cmd, timeout=10):
            if "list-timers" in cmd:
                return ("Mon 02:00:00 clamav-daily-scan.timer\n", 0)
            return ("", 1)

        with patch("endpoint_check.run", side_effect=side_effect):
            status, detail = ec.check_scheduled_task(spec)
        self.assertEqual(status, "pass")
        self.assertIn("timer", detail)

    def test_cron_passes_when_no_timer(self):
        spec = {"timer_pattern": "clam", "cron_pattern": "clamscan"}

        def side_effect(cmd, timeout=10):
            if "list-timers" in cmd:
                return ("", 0)
            if "grep -rl" in cmd:
                return ("/etc/cron.daily/clamscan\n", 0)
            return ("", 1)

        with patch("endpoint_check.run", side_effect=side_effect):
            status, detail = ec.check_scheduled_task(spec)
        self.assertEqual(status, "pass")
        self.assertIn("cron", detail)

    def test_neither_fails(self):
        spec = {"timer_pattern": "clam", "cron_pattern": "clamscan"}
        with patch("endpoint_check.run", return_value=fake_run("", 0)):
            status, _ = ec.check_scheduled_task(spec)
        self.assertEqual(status, "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)