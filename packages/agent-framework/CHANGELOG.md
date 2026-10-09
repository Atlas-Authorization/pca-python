# Changelog

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (Microsoft Agent Framework 1.21.0 (`agent-framework-core`)); run them with `make test-real`.
- Fix: `pca_tool` now returns a real `FunctionTool` on current releases (the `ai_function` decorator it targeted no longer exists) and preserves the tool's settings, and the middleware now calls the zero-argument `call_next` that current releases pass; earlier builds never allowed a call.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
