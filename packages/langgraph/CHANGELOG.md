# Changelog

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (LangGraph 1.2.14 with langchain-core 1.6.9); run them with `make test-real`.
- Fix: The tool wrapper now declares `config: RunnableConfig` so the run config (where the proof travels) reaches the guard, and records its capability in the tool's `metadata`; earlier builds could not wrap a real LangChain tool.
- Fix: A step-up resumed with a bare proof object is now accepted and re-verified.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
