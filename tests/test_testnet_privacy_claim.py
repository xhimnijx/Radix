"""D2: the privacy claim is machine-readable, and it says amounts are public.

The claim in `docs/DECISIONS.md` is one sentence with two phases: ring anonymity now, confidential
amounts when C-1 closes. The point of putting it in `/api/status` is that a client branches on a
field rather than on a document version -- so these tests assert the field exists, says what the
doc says, and cannot quietly flip to claiming confidentiality.
"""

import pathlib
import tempfile

from radix_testnet.node import Node


def fresh_node():
    return Node(data_dir=pathlib.Path(tempfile.mkdtemp()), persist=True, peers=[])


def test_the_status_reports_a_privacy_mode():
    status = fresh_node().status()
    assert "privacy" in status
    privacy = status["privacy"]
    for key in ("mode", "confidential", "ring", "claim"):
        assert key in privacy, f"the privacy report is missing {key!r}"


def test_the_status_does_not_claim_confidential_amounts():
    """The assertion that matters: a false privacy claim is the worst kind of bug here."""
    privacy = fresh_node().status()["privacy"]
    assert privacy["confidential"] is False, (
        "the node claims confidential amounts, which the proof does not provide"
    )
    assert privacy["mode"] == "public-amounts"


def test_the_ring_size_in_the_claim_matches_the_one_the_chain_builds():
    node = fresh_node()
    assert node.status()["privacy"]["ring"] == len(node.chain.pool) - 1, (
        "the advertised ring size does not match the pool the chain actually samples from"
    )


def test_the_decision_record_and_the_rpc_agree():
    """A document and an API that disagree is the failure this test exists to prevent."""
    document = pathlib.Path("docs/DECISIONS.md").read_text(encoding="utf-8")
    assert "amounts are public" in document.lower()
    assert "public-amounts" in document, "the document must name the mode the RPC reports"

    privacy = fresh_node().status()["privacy"]
    assert privacy["mode"] in document
