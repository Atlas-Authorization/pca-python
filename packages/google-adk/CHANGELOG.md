# Changelog

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (Google ADK 2.11.0); run them with `make test-real`.
- Fix: The guarded tool now asks ADK to inject the `ToolContext` even when the tool's own signature does not declare it, so a proof carried in session state is actually seen. Note that a denial raised by `pca_tool` aborts the agent run (fail closed); use `pca_before_tool_callback` to hand the model a deny result instead.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
