"""
Binary Merkle tree over SHA-256 leaves.

build_tree(leaves)          -> MerkleTree
tree.root                   -> bytes (32-byte root hash)
tree.prove(index)           -> list[dict]  (inclusion proof)
verify_proof(root, leaf, proof, index) -> bool
"""

import hashlib
import math


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return _h(left + right)


class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf")
        # Pad to next power of 2
        n = 1 << math.ceil(math.log2(max(len(leaves), 1)))
        pad = _h(b"\x00")
        self._leaves = leaves + [pad] * (n - len(leaves))
        self._n = n
        self._nodes = self._build()

    def _build(self) -> list[bytes]:
        # nodes[0..n-1] are leaves; nodes[n..] are internal (bottom-up)
        layer = [_h(leaf) for leaf in self._leaves]
        all_nodes = [layer]
        while len(layer) > 1:
            layer = [
                _hash_pair(layer[i], layer[i + 1])
                for i in range(0, len(layer), 2)
            ]
            all_nodes.append(layer)
        return all_nodes

    @property
    def root(self) -> bytes:
        return self._nodes[-1][0]

    @property
    def leaf_hashes(self) -> list[bytes]:
        return self._nodes[0]

    def prove(self, index: int) -> list[dict]:
        """Return sibling hashes from leaf to root."""
        proof = []
        for layer in self._nodes[:-1]:
            sibling_idx = index ^ 1  # flip last bit
            proof.append({
                "hash": layer[sibling_idx].hex(),
                "position": "right" if index % 2 == 0 else "left",
            })
            index //= 2
        return proof


def verify_proof(root: bytes, leaf: bytes, proof: list[dict], index: int) -> bool:
    current = _h(leaf)
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "right":
            current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
        index //= 2
    return current == root
