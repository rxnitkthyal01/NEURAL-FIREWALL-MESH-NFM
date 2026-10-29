# Contributing

## Development setup

Use Python 3.12+, then install the editable package and development tools:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy nfm
```

## Security-sensitive changes

- Use maintained standard protocols and libraries; do not implement cryptographic primitives.
- Keep authentication separate from authorization and preserve default deny.
- Add tests for both allowed and denied cases, including malformed input and revocation where relevant.
- Do not add automatic firewall changes without dry-run, rollback, and explicit administrator activation.
- Do not claim a capability until it has been exercised in an isolated test environment.
- Never commit private keys, credentials, database files, or real security event data.

Open a pull request with a concise threat impact, behavior changes, test commands/results, and any limitation introduced.
