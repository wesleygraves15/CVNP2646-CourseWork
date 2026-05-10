"""Tests for the individual check functions — service, port, log pattern."""

import unittest
from unittest.mock import patch

import endpoint_check as ec


def fake_run(stdout="", rc=0):
    return (stdout, rc)


class TestServiceCheck(unittest.TestCase):

    def test_active_service_passes(self):
        spec = {"service": "wazuh-agent"}
        with patch("endpoint_check.run", return_value=fake_run("active\n", 0)):
            status, detail = ec.check_service(spec)
        self.assertEqual(status, "pass")
        self.assertIn("active", detail)

    def test_inactive_service_fails(self):
        spec = {"service": "clamav-daemon"}
        with patch("endpoint_check.run", return_value=fake_run("inactive\n", 3)):
            status, detail = ec.check_service(spec)
        self.assertEqual(status, "fail")
        self.assertIn("inactive", detail)

    def test_unknown_service_fails(self):
        spec = {"service": "nope"}
        with patch("endpoint_check.run", return_value=fake_run("unknown\n", 4)):
            status, _ = ec.check_service(spec)
        self.assertEqual(status, "fail")


class TestPortCheck(unittest.TestCase):

    def test_tcp_listening_passes(self):
        spec = {"port": 3310, "protocol": "tcp"}
        out = "tcp LISTEN 0 30 127.0.0.1:3310 *:* users:((\"clamd\",pid=1234))\n"
        with patch("endpoint_check.run", return_value=fake_run(out, 0)):
            status, detail = ec.check_port(spec)
        self.assertEqual(status, "pass")
        self.assertIn("3310", detail)

    def test_udp_listening_passes(self):
        spec = {"port": 1514, "protocol": "udp"}
        out = "udp UNCONN 0 0 0.0.0.0:1514 0.0.0.0:* users:((\"wazuh-remoted\",pid=1))\n"
        with patch("endpoint_check.run", return_value=fake_run(out, 0)):
            status, _ = ec.check_port(spec)
        self.assertEqual(status, "pass")

    def test_no_match_fails(self):
        spec = {"port": 3310, "protocol": "tcp"}
        with patch("endpoint_check.run", return_value=fake_run("", 0)):
            status, _ = ec.check_port(spec)
        self.assertEqual(status, "fail")

    def test_default_protocol_is_tcp(self):
        """If protocol is missing from the spec, default to TCP."""
        spec = {"port": 3310}
        out = "tcp LISTEN 0 30 127.0.0.1:3310\n"
        with patch("endpoint_check.run", return_value=fake_run(out, 0)):
            status, _ = ec.check_port(spec)
        self.assertEqual(status, "pass")


class TestLogPatternCheck(unittest.TestCase):

    def test_pattern_present_passes(self):
        spec = {
            "path": "/var/ossec/logs/ossec.log",
            "must_contain": "Connected to the server",
        }
        log = "INFO: (4102): Connected to the server ([10.0.0.5]:1514/udp).\n"
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("endpoint_check.run", return_value=fake_run(log, 0)):
            status, _ = ec.check_log_pattern(spec)
        self.assertEqual(status, "pass")

    def test_warn_pattern_warns(self):
        spec = {
            "path": "/var/ossec/logs/ossec.log",
            "must_contain": "Connected to the server",
            "warn_if_contains": "Trying to connect",
        }
        log = "INFO: Trying to connect to server\n"
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("endpoint_check.run", return_value=fake_run(log, 0)):
            status, _ = ec.check_log_pattern(spec)
        self.assertEqual(status, "warn")

    def test_no_match_fails(self):
        spec = {
            "path": "/var/ossec/logs/ossec.log",
            "must_contain": "Connected to the server",
        }
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("endpoint_check.run", return_value=fake_run("unrelated\n", 0)):
            status, _ = ec.check_log_pattern(spec)
        self.assertEqual(status, "fail")

    def test_missing_log_fails(self):
        spec = {"path": "/missing.log", "must_contain": "x"}
        with patch("pathlib.Path.is_file", return_value=False):
            status, _ = ec.check_log_pattern(spec)
        self.assertEqual(status, "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)