"""Append a signed action pack to a SCITT transparency log (RFC 9943) and verify the receipt (native port of transparency.ts of the TypeScript
reference @atlasauth/pca-actions). The statement is a COSE Signed Statement over {ns, version, digest, root, prev}; the receipt is the log's
signed inclusion proof. Keys are the scitt module's native key forms (Ed25519 raw seed / public key, or `cryptography` P-256 keys)."""
from typing import Any, Dict, Optional

from .actions_registry import pack_digest
from .pca import canonical_bytes
from .scitt import sign_statement, statement_payload, verify_receipt
from .scitt_log import TransparencyService, register_statement

PACK_STATEMENT_CONTENT_TYPE = "application/pca-action-pack+json"


def pack_statement_payload(p: dict) -> dict:
    """The payload the registry signs into the log (small: the digest, not the pack)."""
    return {"v": 1, "kind": "pca-action-pack-statement", "ns": p["ns"], "version": p["version"], "digest": pack_digest(p), "root": p["root"], "prev": p["prev"]}


def append_pack_to_log(pack: dict, service: TransparencyService, signer: dict) -> dict:
    """Sign the pack's statement with the registry's COSE key (signer: {alg, key, issuer}) and register it: {statement, receipt, index, root}."""
    statement = sign_statement(pack_statement_payload(pack), signer["alg"], signer["key"], signer["issuer"], "%s@%s" % (pack["ns"], pack["version"]), PACK_STATEMENT_CONTENT_TYPE)
    r = register_statement(statement, service)
    return {"statement": statement, "receipt": r["receipt"], "index": r["index"], "root": r["root"]}


def _statement_is_for(pack: dict, statement: Any) -> bool:
    return statement_payload(statement) == canonical_bytes(pack_statement_payload(pack))


def verify_pack_log_entry(pack: dict, entry: dict, keys: dict, tree_root: Optional[str] = None) -> bool:
    """Does `entry` prove `pack` is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never raises."""
    try:
        return bool(verify_receipt(entry["receipt"], entry["statement"], tree_root, keys["log"], keys["registry"])) and _statement_is_for(pack, entry["statement"])
    except Exception:  # noqa: BLE001
        return False
