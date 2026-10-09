# Changelog

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (Haystack 2.31.0 (`ToolInvoker`, `Agent`) and 3.3.0 (`Agent`; 3.x has no `ToolInvoker`)); run them with `make test-real`.
- Fix: Guarding a real `Tool` now keeps all of its settings (`outputs_to_string`, `inputs_from_state`, `outputs_to_state`, subclasses) and also guards its `async_function`; earlier builds dropped those fields and left the async entry point unguarded.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
