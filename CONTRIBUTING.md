# Contributing

Run the test suite before opening a pull request:

```bash
python -m pip install -e ".[dev]"
pytest
```

Never include real activation keys, certificates, device tokens, account data,
or captured notification content in a commit, issue, or test fixture.

Protocol changes should include:

1. a minimal synthetic frame fixture;
2. a test proving the parser remains size-bounded;
3. a note explaining whether the change was observed on production Apple
   infrastructure or inferred from an existing client.
