# Changelog

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (Pydantic AI 2.54.0 (`pydantic-ai-slim`)); run them with `make test-real`.
- Fix: Pydantic AI's strict tool schema rejects a proof placed in model-supplied arguments before the guard runs, so use `RunContext.deps` to carry the proof.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
