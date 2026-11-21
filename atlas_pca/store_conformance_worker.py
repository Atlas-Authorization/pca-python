"""One client process of the multi-process crash harness (:mod:`atlas_pca.store_conformance_crash`): load the adapter, run the windowed
workload on several threads, record the history to a file. Run as ``python -m atlas_pca.store_conformance_worker '<json config>'``."""
from __future__ import annotations

import json
import sys
import threading
from typing import Any

from .store_conformance_load import load_adapter
from .store_conformance_model import prng
from .store_conformance_runner import FileRecorder, close_clients, drive_windowed, open_clients


def worker_main(cfg: dict) -> None:
    adapter = load_adapter(cfg["module"], cfg["options"])
    rec = FileRecorder(cfg["file"], cfg["proc"])
    clients = open_clients(adapter, cfg["clients"])
    ctx = {"rec": rec, "retentionMs": cfg["retentionMs"], "opTimeoutMs": cfg["opTimeoutMs"]}
    errs: list = []

    def run(i: int, c: Any) -> None:
        try:
            drive_windowed(c, "%sc%d" % (cfg["proc"], i), cfg["kind"], ctx, cfg["namespace"], cfg["windowMs"], cfg["spread"], cfg["values"],
                           cfg["origin"], cfg["deadline"], prng(cfg["seed"] + i))
        except BaseException as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=run, args=(i, c)) for i, c in enumerate(clients)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    close_clients(clients)
    rec.close()
    td = getattr(adapter, "teardown", None)
    if callable(td):
        td()
    if errs:
        raise errs[0]


if __name__ == "__main__":
    try:
        worker_main(json.loads(sys.argv[1]))
    except BaseException as e:  # noqa: BLE001
        sys.stderr.write("pca-store-conformance worker: %s\n" % e)
        sys.exit(1)
    sys.exit(0)
