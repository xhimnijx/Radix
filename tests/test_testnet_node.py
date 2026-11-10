"""The node's HTTP layer, tested through the real socket.

Fast: the chain's verifier is stubbed and the signature codec is replaced, so the
plumbing is exercised in seconds. The real-crypto path is
`tests/test_testnet_end_to_end.py`.
"""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from radix_testnet import chain as C
from radix_testnet.node import Handler, Node
from radix_testnet.tagged import TaggedSpend
from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice.spend import Output


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _post(base, path, payload):
    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        base + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _json(base, path):
    status, body = _get(base, path)
    assert status == 200, body
    return json.loads(body)


@pytest.fixture
def served(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "SIGNATURE_ENCODER", lambda signature: b"")
    monkeypatch.setattr(C, "SIGNATURE_DECODER", lambda blob, depth, rows: None)
    node = Node(data_dir=tmp_path)
    node.chain.verify = lambda parameters, spend: True
    server = ThreadingHTTPServer(("127.0.0.1", 0), type("Bound", (Handler,), {"node": node}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", node, tmp_path
    finally:
        server.shutdown()
        server.server_close()


def _spend(node, rng):
    account = node.faucet.accounts[0]
    indices = node.chain.ring_for(account.public, rng)
    ring_keys = tuple(node.chain.pool[index] for index in indices)
    note = Output(key=node.faucet.accounts[1].public, value=990)
    spend = TaggedSpend(
        anchor=node.chain.anchor,
        input_values=(1000,),
        rings=(ring_keys,),
        outputs=(note,),
        fee=10,
        signatures=(None,),
        tags=((ring.constant(1),),),
    )
    return spend, (indices,)


def test_status_reports_the_chain_and_the_faucet(served):
    base, _node, _tmp = served
    status = _json(base, "/api/status")
    assert status["banner"] == "TESTNET - NO VALUE - NO SECURITY CLAIM"
    assert status["height"] == 0
    assert status["faucet"]["accounts"] == 4
    assert status["faucet"]["balance"] == 4000
    assert status["backend"] == "python"
    assert status["parameters"]["ring"] == 1024
    assert status["parameters"]["tag_rows"] == 1


def test_the_wallet_page_carries_the_disclaimers_and_every_view(served):
    base, _node, _tmp = served
    status, body = _get(base, "/")
    assert status == 200
    page = body.decode()
    for label in ("testnet", "no value", "no security claim"):
        assert label in page.lower()
    for view in ("wallet", "send", "receive", "history", "book", "settings"):
        assert f'data-view="{view}"' in page


def test_accounts_are_listed_with_balances_and_spent_state(served):
    base, _node, _tmp = served
    accounts = _json(base, "/api/accounts")["accounts"]
    assert len(accounts) == 4
    assert accounts[0]["balance"] == 4000
    assert accounts[0]["spent"] is False
    assert [entry["index"] for entry in accounts] == [0, 1, 2, 3]
    assert all(entry["address"].startswith("rtx1") for entry in accounts)


def test_history_is_empty_on_a_fresh_chain(served):
    base, _node, _tmp = served
    assert _json(base, "/api/history")["history"] == []


def test_qr_returns_an_svg(served):
    base, _node, _tmp = served
    status, body = _get(base, "/api/qr?text=rtx1example")
    assert status == 200
    assert body.lstrip().startswith(b"<svg") or b"<svg" in body[:200]
    assert b"</svg>" in body


def test_qr_requires_text(served):
    base, _node, _tmp = served
    status, body = _get(base, "/api/qr")
    assert status == 400
    assert b"text is required" in body


def test_unknown_routes_are_404(served):
    base, _node, _tmp = served
    assert _get(base, "/api/nope")[0] == 404
    assert _post(base, "/api/nope", {})[0] == 404


def test_malformed_json_is_400(served):
    base, _node, _tmp = served
    request = urllib.request.Request(
        base + "/api/mine", data=b"not json", headers={"Content-Type": "application/json"}
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=10)
    assert error.value.code == 400


def test_a_bad_address_is_refused_with_a_reason(served):
    base, _node, _tmp = served
    status, body = _post(base, "/api/send", {"to": "not-an-address", "amount": 10, "fee": 1})
    assert status == 400
    assert "error" in body


def test_mining_an_empty_mempool_is_400(served):
    base, _node, _tmp = served
    status, body = _post(base, "/api/mine", {})
    assert status == 400
    assert "nothing to mine" in body["error"]


def test_address_book_round_trips_and_persists(served):
    base, _node, tmp_path = served
    status, body = _post(base, "/api/addressbook", {"name": "Alice", "address": "rtx1alice"})
    assert status == 200
    assert body["addressbook"][0]["name"] == "Alice"
    assert _json(base, "/api/addressbook")["addressbook"][0]["address"] == "rtx1alice"
    assert (tmp_path / "addressbook.json").exists()

    # saving the same address again replaces rather than duplicates
    _post(base, "/api/addressbook", {"name": "Alice B", "address": "rtx1alice"})
    book = _json(base, "/api/addressbook")["addressbook"]
    assert len(book) == 1 and book[0]["name"] == "Alice B"


def test_settings_round_trip(served):
    base, _node, tmp_path = served
    assert _json(base, "/api/settings")["settings"] == {}
    status, body = _post(base, "/api/settings", {"theme": "light"})
    assert status == 200 and body["settings"]["theme"] == "light"
    assert _json(base, "/api/settings")["settings"]["theme"] == "light"
    assert (tmp_path / "settings.json").exists()


def test_a_submitted_transaction_can_be_mined_and_appears_in_history(served):
    base, node, _tmp = served
    spend, indices = _spend(node, __import__("random").Random(3))
    payload = C.spend_to_wire(spend, indices)

    status, body = _post(base, "/api/tx", payload)
    assert status == 200, body
    assert _json(base, "/api/status")["mempool"] == 1
    pending = _json(base, "/api/history")["history"]
    assert pending[0]["status"] == "pending"

    status, mined = _post(base, "/api/mine", {})
    assert status == 200 and mined["transactions"] == 1
    assert _json(base, "/api/status")["height"] == 1

    confirmed = _json(base, "/api/history")["history"]
    assert confirmed[0]["status"] == "confirmed"
    assert confirmed[0]["height"] == 1


def test_state_survives_a_restart(served):
    base, node, tmp_path = served
    spend, indices = _spend(node, __import__("random").Random(5))
    _post(base, "/api/tx", C.spend_to_wire(spend, indices))
    _post(base, "/api/mine", {})
    height = node.chain.height

    reloaded = Node(data_dir=tmp_path)
    reloaded.chain.verify = lambda parameters, spend: True
    assert reloaded.chain.height == height
    assert len(reloaded.chain.outputs) == 2
    assert reloaded.chain.anchor == node.chain.anchor
    assert len(reloaded.chain.spent_tags) == 1


def test_a_config_file_is_written_on_first_start(served):
    _base, _node, tmp_path = served
    import json as jsonlib

    config = jsonlib.loads((tmp_path / "config.json").read_text())
    assert config["host"] == "127.0.0.1"
    assert config["port"] == 8642
    assert config["log_level"] == "info"


def test_events_are_logged_as_json_lines(served):
    _base, node, tmp_path = served
    spend, indices = _spend(node, __import__("random").Random(9))
    node.submit_raw(C.spend_to_wire(spend, indices))
    node.mine()

    lines = (tmp_path / "node.log").read_text().strip().splitlines()
    events = [json.loads(line) for line in lines]
    names = [entry["event"] for entry in events]
    assert "node.start" in names
    assert "chain.ready" in names
    assert "tx.accepted" in names
    assert "block.mined" in names
    for entry in events:
        assert "ts" in entry and "event" in entry


def test_a_rejected_request_is_logged_with_a_reason(served):
    base, _node, tmp_path = served
    _post(base, "/api/send", {"to": "nope", "amount": 1, "fee": 1})
    lines = (tmp_path / "node.log").read_text().strip().splitlines()
    rejections = [
        json.loads(line) for line in lines if json.loads(line)["event"] == "request.rejected"
    ]
    assert rejections
    assert rejections[0]["route"] == "/api/send"
    assert "reason" in rejections[0]


def test_the_auto_miner_settles_the_mempool_by_itself(tmp_path, monkeypatch):
    import time

    from radix_testnet.app import start_auto_miner

    monkeypatch.setattr(C, "SIGNATURE_ENCODER", lambda signature: b"")
    monkeypatch.setattr(C, "SIGNATURE_DECODER", lambda blob, depth, rows: None)
    node = Node(data_dir=tmp_path, persist=False)
    node.chain.verify = lambda parameters, spend: True

    spend, indices = _spend(node, __import__("random").Random(13))
    node.chain.submit(spend, indices)
    assert node.chain.mempool

    start_auto_miner(node, interval=0.05)
    # 5 seconds was enough alone and not always enough under a full-suite load, where this
    # test failed roughly one run in three. The assertion is unchanged -- a block must be
    # mined and the mempool drained -- but the wait is long enough not to race the scheduler.
    deadline = time.time() + 60
    while time.time() < deadline and node.chain.height == 0:
        time.sleep(0.05)
    assert node.chain.height == 1, (
        "the auto-miner did not produce a block within 60 s; it is started in a background "
        "thread, so a hang here means the thread died or the lock is held"
    )
    assert not node.chain.mempool


def test_a_config_with_a_bom_still_loads(tmp_path):
    (tmp_path / "config.json").write_bytes(b'\xef\xbb\xbf{"port": 9999}')
    from radix_testnet import store

    assert store.load_config(tmp_path)["port"] == 9999


def test_a_malformed_config_falls_back_to_defaults(tmp_path):
    (tmp_path / "config.json").write_text("{not json")
    from radix_testnet import store

    config = store.load_config(tmp_path)
    assert config["port"] == 8642
    assert config["auto_mine"] is False


def test_a_corrupt_chain_refuses_to_start_rather_than_resetting(tmp_path):
    (tmp_path / "chain.json").write_text("{not json")
    with pytest.raises(Exception) as error:
        Node(data_dir=tmp_path)
    assert "could not be read" in str(error.value)
