# endpoint_check.py

A small Python tool for verifying CCDC Inject **SVRA12T — Configure End-Point
Protection Software**. The inject asks the team to install Wazuh (centralized
monitoring) and ClamAV (antivirus) across every Linux server, then submit
a memo with proof everything is running. This tool doesn't install anything —
it reads a JSON config describing what to check and runs all the checks in
one shot, so the team doesn't have to remember six commands per box.

## Setup

```
git clone <repo>
cd <repo>
python3 --version          # 3.7 or higher
```

No `pip install` step needed — the tool uses only the Python standard
library. (See `requirements.txt` for context.)

## Usage

```
python3 src/endpoint_check.py
```

The tool auto-detects whether it's running on a Wazuh manager or agent
box, then loads the appropriate config from `data/`. Override the
config explicitly if you want:

```
python3 src/endpoint_check.py --config data/config_agent.json
python3 src/endpoint_check.py --config data/config_manager.json
```

To save the results as JSON for inclusion in the inject memo:

```
python3 src/endpoint_check.py --output results.json
```

Output looks like:

```
Endpoint protection check  (host: ecom)
Config: config_agent.json  (wazuh-agent-with-clamav)

  [ OK ] Wazuh agent service          wazuh-agent is active
  [ OK ] Wazuh agent connectivity     found expected pattern in log
  [ OK ] ClamAV daemon service        clamav-daemon is active
  [ OK ] ClamAV freshclam service     clamav-freshclam is active
  [ OK ] ClamAV TCP socket            tcp port 3310 is listening
  [WARN] ClamAV signatures            signatures are 9.2 days old (max 7)
  [ OK ] ClamAV scheduled scan        cron entry matching 'clamscan' found

Summary: 6 pass, 1 warn, 0 fail
```

Exit code 0 if all checks passed, 1 otherwise — so the tool can be chained
into other scripts.

## CLI reference

| Flag             | Description                                                     |
|------------------|-----------------------------------------------------------------|
| `--config PATH`  | JSON config to use (default: auto-detected from system services)|
| `--output PATH`  | Write results as JSON to this file (default: stdout only)       |

## Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | All checks passed                                |
| 1    | One or more checks failed                        |
| 2    | Config file not found or invalid JSON            |

## Features

- **Five check types** — service status, port listening, log pattern
  search, file freshness, scheduled task. Each maps to a real
  verification command (`systemctl is-active`, `ss -ltnp`, etc).
- **Data-driven configuration** — adding a new check is one entry in
  the JSON config. No code changes needed.
- **Three result states** — pass / warn / fail. Warn catches the
  in-between cases (signatures slightly stale, listening on unix socket
  instead of TCP) where the service is working but not perfectly.
- **JSON output** — `--output results.json` produces a structured
  report ready for inclusion in the inject's memo response.
- **Auto-detect role** — checks `systemctl list-unit-files` to decide
  whether this is a Wazuh manager or an agent and picks the right config.

## Tests

```
pytest tests
```

Or with unittest:

```
python3 -m unittest discover -s tests -t .
```

34 tests across four files. All should pass on a clean Python install
without Wazuh or ClamAV present. The `-t .` (top-level directory) flag
is needed for unittest because `conftest.py` at the project root sets
up the path so tests can import `endpoint_check` from `src/`.

### What each test file covers

- **`test_checks.py`** (11 tests) — the three basic check types:
  service status (pass / inactive / unknown service), port listening
  (TCP / UDP / no match / default protocol), and log pattern matching
  (pattern present / warning pattern / no match / missing log file).
- **`test_clamav.py`** (7 tests) — the ClamAV-specific checks:
  signature freshness (recent / stale / missing / default max-age) and
  scheduled-task discovery (systemd timer / cron entry / neither).
- **`test_orchestration.py`** (10 tests) — the dispatch and reporting
  layer: `run_checks` correctly routes each type to its function,
  handles unknown types gracefully, catches exceptions raised by checks,
  and includes the right fields in results. Plus `detect_role` and
  `build_report` coverage.
- **`test_configs.py`** (6 tests) — validates the bundled JSON files in
  `data/`. Catches breakage like a typo in a check type name or
  a missing required field, which the function-level tests can't see.

### How the tests work

The tests use `unittest.mock.patch` to substitute fake return values for
`subprocess.run` and for `pathlib.Path` methods. Instead of *actually*
running `systemctl is-active wazuh-agent` (which fails on a development
laptop because the service doesn't exist), each test feeds the function
the kind of output a real command would produce and asserts the function
interprets it correctly.

This means the tests can run on any laptop with Python installed — no
real Wazuh, ClamAV, or systemd required.

### Honest limits of this test suite

The tests verify the tool's **parsing and decision logic** — given some
representative command output, do the check functions interpret it
correctly? They do not verify that the tool produces accurate results
against a real Wazuh + ClamAV installation. I authored the mocked
outputs by reading documentation and the inject text, but a real install
may emit slightly different formats (different log timestamps, different
`ss` column layouts depending on distro, etc.).

Real-environment validation is the work that needs to happen during the
5-day practice window before competition. The likely outcomes:

- Most checks work as designed.
- A few may need their parsing logic adjusted to match actual output.
- One or two new check types may be worth adding once we see what
  Wazuh actually logs.

Each of these is a small fix in `endpoint_check.py` plus a small JSON
config edit. The structure of the tool is designed to make those
adjustments easy.

## Project structure

```
src/
    endpoint_check.py        # main tool (~250 lines)
data/
    config_agent.json        # JSON config for agent boxes
    config_manager.json      # JSON config for the manager box
    expected_output_agent.json  # what the tool produces with --output
tests/
    test_checks.py           # service, port, log_pattern checks
    test_clamav.py           # signature freshness, scheduled task
    test_orchestration.py    # run_checks, build_report, role detection
    test_configs.py          # bundled JSON configs are valid
conftest.py                  # pytest config (adds src/ to path)
requirements.txt             # dependencies (none — stdlib only)
README.md                    # this file
REFLECTION.md                # required reflection responses
AI_USAGE.md                  # AI assistance disclosure
```

## Notes

- **Run as root for full coverage.** Some checks (port listeners,
  reading `/var/ossec/logs/ossec.log`) require root to see everything.
  Without root, those checks may fail even when things are configured
  correctly.
- **Linux only.** The checks rely on `systemctl`, `ss`, `tail`, etc.
  Running on Windows or macOS will fail every check — the tool is
  designed for the Linux servers in the CCDC environment.
- **Verify, don't install.** This tool deliberately doesn't install
  Wazuh or ClamAV. Automating installs of security software during
  competition is risky; if an install fails partway through, that's
  worse than no automation. The inject's install steps are run by hand;
  this tool confirms they worked.
- **Config files describe what to check, not how.** Adding a new check
  type (e.g., verifying a specific Wazuh module is enabled in
  `ossec.conf`) means adding a new function in `endpoint_check.py` plus
  a new entry in the JSON config. The two are kept separate on purpose.

## What it doesn't do

- Doesn't take screenshots. The inject's deliverables ask for a screenshot
  of the Wazuh dashboard — that's still a human action.
- Doesn't verify the Windows side of the inject. Linux only.
- Doesn't check that scans have actually *run*, only that they're scheduled.