"""multiInstance: a process-scoped replay store is refused when several instances serve the guard (reference require-pca.ts): one
PCActn would replay once per instance. A store declares `scope`; one that declares nothing is shared."""
import pytest

from atlas_pca.authorize import MULTI_INSTANCE_ERROR, AuthorizeOptions, MemoryStateStore, SqliteStateStore, StateStore, authorize

TEXT = "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)"


def test_the_text_is_the_agreed_one():
    assert MULTI_INSTANCE_ERROR == TEXT


def test_the_bundled_stores_declare_their_scope(tmp_path):
    assert MemoryStateStore().scope == "process"
    assert SqliteStateStore(str(tmp_path / "s.db")).scope == "shared"
    assert StateStore.scope is None


def test_a_process_store_with_multi_instance_is_refused_at_construction():
    with pytest.raises(ValueError) as e:
        AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False, multi_instance=True)
    assert str(e.value) == "AuthorizeOptions: " + TEXT


def test_a_shared_or_undeclared_store_is_fine(tmp_path):
    AuthorizeOptions(state_store=SqliteStateStore(str(tmp_path / "s.db")), is_revoked=lambda p, g: False, multi_instance=True)

    class Custom(StateStore):
        pass

    AuthorizeOptions(state_store=Custom(), is_revoked=lambda p, g: False, multi_instance=True)
    AuthorizeOptions(state_store=Custom(), is_revoked=lambda p, g: False)


def test_the_default_does_not_refuse_the_process_store():
    AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False)
    AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False, multi_instance=False)
    AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False, multi_instance=None)


def test_authorize_refuses_a_process_store_with_multi_instance():
    r = authorize({}, operation={"verb": "v", "resource": "r", "params": {}}, audience="a", resolve_grant=lambda ref: None,
                  state_store=MemoryStateStore(), is_revoked=lambda p, g: False, multi_instance=True)
    assert r.allow is False and r.status == 403
    assert r.reason == "authorize_config: " + TEXT
    assert r.missing == ["state_store"]
