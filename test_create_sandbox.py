"""create_sandbox: the single entry point composing the receipt log, the handle table and the guest hosts. The table's runtime
class must be exactly what the shared runtime-claim corpus says the claim verifies to (never above what a WASM host proves); with
no claim, or one that does not verify, it is `none`. The module-level refusals happen before the engine is needed."""
import pytest

from atlas_pca import sandbox as S
from atlas_pca.sandbox_wasm import Sandbox, create_sandbox
from base_oracle import load_ref

_, BY_FN = load_ref("sandbox")
CLAIMS = BY_FN["verifiedRuntimeClass"]


def test_no_claim_is_class_none_and_shares_one_log():
    sb = create_sandbox({"fetch": lambda op: b"x"})
    assert isinstance(sb, Sandbox) and sb.table.runtime_class == "none" and isinstance(sb.log, S.ReceiptLog)
    assert sb.table.size == 0


@pytest.mark.parametrize("c", CLAIMS, ids=lambda c: c["name"])
def test_table_class_follows_the_verified_claim(c):
    claim, trust = c["args"]
    sb = create_sandbox({}, runtime_claim={"claim": claim, "trust": trust})
    assert sb.table.runtime_class == c["out"]


def test_refusals_before_any_run():
    sb = create_sandbox({}, max_module_bytes=8)
    assert sb.run(b"\x00asm\x01\x00\x00\x00\x00", fuel=1000)["reason"] == "module_size"
    assert sb.run(b"", fuel=1000) == {"ok": False, "reason": "module_size"}
    assert sb.run(b"\x00asm\x01\x00\x00\x00", fuel=None) == {"ok": False, "reason": "bad_fuel"}
