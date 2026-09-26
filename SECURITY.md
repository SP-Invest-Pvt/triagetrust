# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) rather than in a public issue.
Include the affected version or commit, steps to reproduce, and the impact you expect.

You can expect an acknowledgement within 5 working days. This is a personal portfolio project
maintained on a best-effort basis, so fixes are prioritised by severity.

## Scope

In scope: the `triagetrust` package, its CLI, and the scripts and workflows in this repository.

Out of scope: the deliberately vulnerable test fixtures under `tests/fixtures/`, and the OWASP
Benchmark, which is downloaded at run time and intentionally contains vulnerable code.

## Handling secrets

The project never needs credentials in the repository. LLM API keys are read from environment
variables or GitHub Actions secrets only, and LLM responses are cached locally under `.cache/`,
which is git-ignored.
