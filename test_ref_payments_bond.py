"""Differential replay of atlas_pca.payments.open_charge_bond (the optimistic bonded claim over a charge PCActn) against vectors generated from the
TypeScript reference (@atlasauth/pca-payments). The signature is Ed25519, so the claim is compared in full. The corpus' authorizeChargeCore cases
need the reference's built-in policy engine, which the native port takes as an injected callable, so they are not replayed here."""
from atlas_pca import payments as P
from atlas_pca.pca import unb64u
from base_oracle import load_ref, run

COUNT, CASES = load_ref("payments-java-extra")


def test_open_charge_bond_matches_reference():
    assert set(CASES) == {"authorizeChargeCore", "openChargeBond"}
    ran, _ = run(CASES["openChargeBond"], lambda p, opts, seed: P.open_charge_bond(p, opts, unb64u(seed), True))
    assert ran == len(CASES["openChargeBond"])
