"""Tests for run_checks (orchestration) and detect_role (auto-detection)."""

import unittest
from unittest.mock import patch

import endpoint_check as ec


def fake_run(stdout="", rc=0):
    return (stdout, rc)


class TestRoleDetection(unittest.TestCase):

    def test_manager_detected(self):
        with patch("endpoint_check.run",
                   return_value=fake_run("wazuh-manager.service enabled\n", 0)):
            self.assertEqual(ec.detect_role(), "manager")

    def test_agent_detected(self):
        with patch("endpoint_check.run",
                   return_value=fake_run("wazuh-agent.service enabled\n", 0)):
            self.assertEqual(ec.detect_role(), "agent")

    def test_neither_returns_unknown(self):
        with patch("endpoint_check.run",
                   return_value=fake_run("other-service\n", 0)):
            self.assertEqual(ec.detect_role(), "unknown")

    def test_manager_wins_when_both_present(self):
        out = "wazuh-manager.service enabled\nwazuh-agent.service enabled\n"
        with patch("endpoint_check.run", return_value=fake_run(out, 0)):
            self.assertEqual(ec.detect_role(), "manager")


class TestRunChecks(unittest.TestCase):
    """Verify the orchestration loop dispatches to the right check function
    and handles unknown types gracefully."""

    def test_dispatches_to_correct_function(self):
        config = {
            "checks": [
                {"name": "Test svc", "type": "service", "service": "foo"},
            ]
        }
        with patch("endpoint_check.check_service",
                   return_value=("pass", "ok")) as mock_fn:
            results = ec.run_checks(config)
        mock_fn.assert_called_once()
        self.assertEqual(results[0]["status"], "pass")
        self.assertEqual(results[0]["name"], "Test svc")

    def test_unknown_type_fails_gracefully(self):
        config = {
            "checks": [
                {"name": "Bogus", "type": "not_a_real_type"},
            ]
        }
        results = ec.run_checks(config)
        self.assertEqual(results[0]["status"], "fail")
        self.assertIn("unknown check type", results[0]["detail"])

    def test_check_exception_caught(self):
        """If a check function raises, it shouldn't crash the whole run."""
        config = {
            "checks": [
                {"name": "Bad", "type": "service", "service": "x"},
            ]
        }
        with patch("endpoint_check.check_service",
                   side_effect=RuntimeError("boom")):
            results = ec.run_checks(config)
        self.assertEqual(results[0]["status"], "fail")
        self.assertIn("RuntimeError", results[0]["detail"])

    def test_results_include_type_field(self):
        """The output JSON should include the check type for clarity."""
        config = {
            "checks": [
                {"name": "X", "type": "service", "service": "foo"},
            ]
        }
        with patch("endpoint_check.check_service",
                   return_value=("pass", "ok")):
            results = ec.run_checks(config)
        self.assertEqual(results[0]["type"], "service")


class TestBuildReport(unittest.TestCase):
    """The JSON output report should have the expected shape."""

    def test_report_has_expected_keys(self):
        config = {"name": "test-config"}
        results = [{"name": "X", "status": "pass", "detail": "ok"}]
        report = ec.build_report(config, results)
        for key in ["host", "config", "timestamp", "summary", "checks"]:
            self.assertIn(key, report)

    def test_summary_counts_correctly(self):
        config = {"name": "x"}
        results = [
            {"name": "a", "status": "pass", "detail": ""},
            {"name": "b", "status": "pass", "detail": ""},
            {"name": "c", "status": "warn", "detail": ""},
            {"name": "d", "status": "fail", "detail": ""},
        ]
        report = ec.build_report(config, results)
        self.assertEqual(report["summary"], {"pass": 2, "warn": 1, "fail": 1})


if __name__ == "__main__":
    unittest.main(verbosity=2)