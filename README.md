# pca-python

Proof-Carrying Authority (PCA) verifier for Python. **Preview.**

PCA is authF: instead of verifying a token, you verify a proof-carrying action (a PCActn) - the capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. This is a reference verifier that passes the shared conformance vectors.

> Preview: the wire format and API may change before 1.0.

## Install

Preview, not yet on PyPI: `pip install git+https://github.com/Atlas-Authorization/pca-python` (package `atlas-pca`, import `atlas_pca`). Optional `pip install cryptography` for native Ed25519; a pure-Python fallback is built in.

## Verify

```python
from atlas_pca import verify_pcactn_core

verdict = verify_pcactn_core(pcactn, grant)  # both parsed JSON dicts
if verdict.allow:
    print("authorized")  # chain, plan_inclusion, leaf_signature, counter all passed
else:
    print(verdict.reason, verdict.checks)
```

## Conformance tests

The shared golden vectors are vendored in `conformance/` (synced from the hub). Run:

```
python3 -m unittest test_conformance
```

The reference verifier must produce the same `allow` and the same pass/fail for each of the four checks on every vector.

## Links

- Hub (spec, other languages): https://github.com/Atlas-Authorization/pca
- Live docs: https://atlasauth.net/pca
- TypeScript reference: npm `@atlasauth/pca`

## License

MIT
