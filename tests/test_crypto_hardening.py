import pytest

from zerotrust.crypto.schnorr import (
    batch_verify,
    keygen,
    sign,
    verify,
    verify_knowledge,
    prove_knowledge,
)
from zerotrust.crypto.merkle import MerkleTree, verify_proof


def test_schnorr_rejects_malformed_signature_without_raising():
    sk, pk = keygen()
    assert verify(pk, b"message", sign(sk, b"message"))
    assert verify(pk, b"message", (1, 0)) is False
    assert verify(pk, b"message", ("not-an-int", 0)) is False
    assert verify(pk, b"message", (2, -1)) is False
    assert verify(pk, b"message", (2, 0, 1)) is False


def test_knowledge_proof_rejects_missing_or_wrong_shaped_fields():
    assert verify_knowledge({}, b"statement") is False
    assert verify_knowledge(None, b"statement") is False
    sk, _ = keygen()
    proof = prove_knowledge(sk, b"statement")
    assert verify_knowledge(proof, b"statement")
    assert not verify_knowledge(proof, b"other statement")


def test_batch_verify_rejects_malformed_entries():
    sk, pk = keygen()
    sig = sign(sk, b"message")
    assert batch_verify([(pk, b"message", sig)])
    assert not batch_verify([(pk, b"message", (1, -1))])
    assert not batch_verify([("bad-key", b"message", sig)])


def test_merkle_proof_rejects_bad_index_and_position():
    tree = MerkleTree([b"alpha", b"beta", b"gamma"])
    proof = tree.prove(1)
    assert verify_proof(tree.root, b"beta", proof, 1)
    assert not verify_proof(tree.root, b"beta", proof, -1)
    assert not verify_proof(tree.root, b"beta", proof, 99)

    tampered = [dict(step) for step in proof]
    tampered[0]["position"] = "right"
    assert not verify_proof(tree.root, b"beta", tampered, 1)


def test_merkle_prove_rejects_padding_leaf_index():
    tree = MerkleTree([b"only"])
    with pytest.raises(IndexError):
        tree.prove(1)
