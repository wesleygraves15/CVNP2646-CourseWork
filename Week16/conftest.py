"""Pytest configuration.

Adds src/ to sys.path so tests can import endpoint_check directly.
pytest loads this automatically on test runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))