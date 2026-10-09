# Changelog

## 0.2.0

- New normative check `grant_ref_bound`: the signed `grant_ref` must equal `cap_chain[0].id`. Proofs that
  previously verified with a mismatched `grant_ref` are now rejected (behaviour change).
- Aligned with the 172-vector shared conformance corpus (strings ordered by UTF-8 bytes wherever they feed a
  hash or commitment).
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
