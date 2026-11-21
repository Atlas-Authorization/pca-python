"""`close()` on the SQLite stores: every connection (all threads) is released so the file can be removed on Windows, and the store stays usable."""
import os
import threading

import pytest

from atlas_pca import SqliteStateStore
from atlas_pca.atomic_kv import SqliteAtomicKv


def _other_thread_conn(s):
    t = threading.Thread(target=s._conn)
    t.start()
    t.join()


@pytest.mark.parametrize("cls", [SqliteAtomicKv, SqliteStateStore])
def test_close_releases_every_connection_and_the_store_reopens(tmp_path, cls):
    s = cls(os.path.join(str(tmp_path), "s.db"))
    main = s._conn()
    _other_thread_conn(s)
    assert len(s._conns) == 2
    s.close()
    assert s._conns == []
    with pytest.raises(Exception):
        main.execute("SELECT 1")  # the connection is really closed
    s.close()  # idempotent
    if cls is SqliteAtomicKv:
        s.set("k", 1)
        assert s.get("k") == 1
    else:
        assert s.claim("k", 1).ok is True
    assert len(s._conns) == 1
    s.close()
    os.remove(os.path.join(str(tmp_path), "s.db"))  # no handle left open
