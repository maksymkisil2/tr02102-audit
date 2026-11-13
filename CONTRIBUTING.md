# Contributing

Thanks for taking a look. Issues and pull requests are welcome, especially
corrections to the transcribed standards.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

CI runs exactly those four commands, plus the Docker lab and a container
build. A pull request needs them green.

## What a change should come with

- **A test.** New behaviour gets a test; a bug fix gets the test that would
  have caught it. Tests for anything that parses data from the network belong
  in `tests/test_wire.py` and must include malformed input.
- **Type annotations.** `mypy` runs in strict mode.
- **A reason in the commit message.** What changed is visible in the diff;
  why it changed is not.

## Correcting or adding a standard

This is the most useful kind of contribution, and the one with the strictest
rules, because a wrong line here silently changes every audit result.

- Every rule cites the part, edition and section it comes from.
- Rules are transcribed from the official document, in its original language
  where there is one. Keep `transcription: draft` until a second person has
  checked every rule against that document.
- A change that alters the verdict on a lab target updates the expected
  results in the same pull request.
- Add a test for at least one point where the new standard disagrees with one
  that is already there. Those disagreements are the reason this tool exists.

The format, the operators and the full procedure are in
[docs/STANDARDS.md](docs/STANDARDS.md). Changes under
`src/tr02102_audit/standards/` and `.github/` need a review by the code owner.

## Scope

This is an audit tool: it reports what a server accepts and how that compares
with published guidance. It does not exploit weaknesses, discover hosts or
scan ranges, and it will not grow those features.

## Reporting a vulnerability

Not through an issue, please. [SECURITY.md](SECURITY.md) explains the private
reporting route and what counts as a vulnerability in this tool.
