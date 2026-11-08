import multiprocessing

from radix_core.providers import AeadNonceRegistry, NonceReuseError


def _reserve_pair_in_child(database_path, queue):
    try:
        AeadNonceRegistry(max_entries=None, database_path=database_path).reserve(
            b"multiprocess key".ljust(32, b"!"), b"unique nonce"[:12]
        )
        queue.put("reserved")
    except NonceReuseError:
        queue.put("duplicate")
    except Exception as exc:  # surface child failures as assertions in the parent
        queue.put(f"error:{type(exc).__name__}:{exc}")


def test_sqlite_nonce_reservation_is_unique_across_processes(tmp_path):
    database = str(tmp_path / "multiprocess-nonces.sqlite3")
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    workers = [
        context.Process(target=_reserve_pair_in_child, args=(database, queue))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    results = []
    for _ in workers:
        results.append(queue.get(timeout=20))
    for worker in workers:
        worker.join(timeout=20)
        if worker.is_alive():
            worker.terminate()
            worker.join()
        assert worker.exitcode == 0
    queue.close()
    assert sorted(results) == ["duplicate", "reserved"]
