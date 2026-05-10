# AI Usage Log

I used Claude (Anthropic) for most of this project. Here's roughly how
and what I caught along the way.

## Where I used it

- Talking through what to build. The first few conversations were me
  describing the inject and us figuring out what the tool should do.
- Writing most of the Python. Most of the code in `endpoint_check.py` and the
  tests was drafted by Claude based on what I asked for.
- Drafting the README and writeup, which I then edited.

What I did myself: read the inject and the team packet, decided on the
verify-don't-install approach, made the call to keep it Linux-only,
ran everything to make sure it worked.

## A couple of example prompts

**"Should I build a tool that automates the install, or one that
verifies after install?"** — Claude argued for verification, basically
because automated installs of security software during competition is
risky. If the wrapper crashes mid-install, that's worse than just
running the install commands by hand. That answer set the scope of
the whole project.

**"Make this data-driven with a JSON config."** — Claude rewrote the
tool so the checks come from a JSON file instead of being hardcoded.
This actually exposed a bug too (see below).

## Stuff I pushed back on or caught

**I cut a lot.** Early on Claude wanted me to build a whole suite of
tools — a network monitor, a host change detector, a hardening
checklist, etc. I cut it down to one tool because I couldn't test
most of that without a real CCDC environment.

**SSH-open advice was wrong.** At one point Claude wrote a hardening
checklist that suggested keeping SSH open on production boxes. I caught
that because I'd read the team packet — it says only scored services
should be exposed externally, and SSH isn't scored. Good reminder that
Claude doesn't read the source docs you're working from.

**A real bug in the JSON dispatch.** When the tool got refactored to
read checks from a JSON config, my tests started failing weirdly —
`mock.assert_called_once()` said the function wasn't called even
though it clearly was. Turned out to be a late-binding issue: the
dispatch dict captured function references at import time, so mocks
couldn't intercept them. Claude proposed the fix (use function names
as strings, look them up with `getattr` each time), but I had to walk
through *why* the original was broken before accepting it. Wouldn't
have caught that without paying attention.

Original (broken — function refs captured at import time, can't be patched):

```python
CHECK_TYPES = {
    "service": check_service,
    "port": check_port,
    "log_pattern": check_log_pattern,
    # ...
}
runner = CHECK_TYPES.get(check_type)
```

Fixed version (looks up the function each time):

```python
type_to_fn = {
    "service": "check_service",
    "port": "check_port",
    "log_pattern": "check_log_pattern",
    # ...
}
runner = getattr(ec_self, fn_name)
```

## How I verified the code

- Ran the 34 tests on my laptop. All pass on a clean Python install.
- Ran the tool end-to-end with the sample JSON configs to confirm
  it actually loads them, dispatches checks correctly, and writes the
  expected output shape.
- Read every function and verified changes. If I couldn't, I asked
  Claude to simplify or explain until I could.
- Limit: I didn't test against a real Wazuh + ClamAV install
  because I don't have access to one yet. The tests verify the parsing
  logic. The real-environment validation is something for the practice
  week before competition.