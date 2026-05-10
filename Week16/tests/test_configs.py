"""Tests that the bundled JSON configs in data/ are valid and complete."""

import json
import unittest
from pathlib import Path

import endpoint_check as ec


SAMPLE_DIR = Path(__file__).parent.parent / "data"


class TestSampleConfigs(unittest.TestCase):

    def test_agent_config_is_valid_json(self):
        path = SAMPLE_DIR / "config_agent.json"
        self.assertTrue(path.is_file(), f"missing: {path}")
        with path.open() as f:
            config = json.load(f)
        self.assertIn("checks", config)
        self.assertGreater(len(config["checks"]), 0)

    def test_manager_config_is_valid_json(self):
        path = SAMPLE_DIR / "config_manager.json"
        self.assertTrue(path.is_file(), f"missing: {path}")
        with path.open() as f:
            config = json.load(f)
        self.assertIn("checks", config)
        self.assertGreater(len(config["checks"]), 0)

    def test_all_check_types_in_configs_are_known(self):
        """If a config references an unknown check type, that's a bug."""
        for filename in ["config_agent.json", "config_manager.json"]:
            with (SAMPLE_DIR / filename).open() as f:
                config = json.load(f)
            for check in config["checks"]:
                self.assertIn(
                    check["type"], ec.CHECK_TYPES,
                    f"{filename} references unknown check type: {check['type']}",
                )

    def test_agent_config_has_required_checks(self):
        """The agent config should cover Wazuh + ClamAV per the inject."""
        with (SAMPLE_DIR / "config_agent.json").open() as f:
            config = json.load(f)
        names = [c["name"] for c in config["checks"]]
        # Spot-check a few we know need to be there
        self.assertTrue(any("Wazuh agent" in n for n in names))
        self.assertTrue(any("ClamAV daemon" in n for n in names))
        self.assertTrue(any("3310" in c.get("name", "") or c.get("port") == 3310
                            for c in config["checks"]))

    def test_manager_config_has_manager_specific_checks(self):
        """Manager config should include 1514/1515 ports."""
        with (SAMPLE_DIR / "config_manager.json").open() as f:
            config = json.load(f)
        ports = [c.get("port") for c in config["checks"]]
        self.assertIn(1514, ports)
        self.assertIn(1515, ports)

    def test_expected_output_is_valid_json(self):
        path = SAMPLE_DIR / "expected_output_agent.json"
        self.assertTrue(path.is_file(), f"missing: {path}")
        with path.open() as f:
            output = json.load(f)
        # Match the shape build_report() produces
        for key in ["host", "config", "timestamp", "summary", "checks"]:
            self.assertIn(key, output)


if __name__ == "__main__":
    unittest.main(verbosity=2)