# Contributing

Use Python 3.14 and the committed `uv.lock`. A pull request must pass linting, formatting, strict type checking, tests with at least 90% line coverage, dependency audit, container scan, Bicep validation, and rendered Kubernetes policy checks.

## Comment policy

- Give every public module, class, function, MCP tool, script, and deployment input a useful docstring or description.
- Add inline comments where they preserve reasoning that the code cannot express: protocol compatibility, authentication boundaries, token-claim mapping, key rotation, public exposure, or cost constraints.
- Do not comment obvious assignments or restate resource names. Prefer an ADR when a decision spans multiple subsystems.
- Never place tokens, Apple user data, email addresses, `.p8` contents, authorization codes, or real tenant secrets in comments, fixtures, logs, screenshots, or commit messages.

Run `make check` before opening a pull request. Security changes require tests showing both the accepted case and the relevant rejection cases.

