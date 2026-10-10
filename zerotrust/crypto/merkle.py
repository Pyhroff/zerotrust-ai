"""
Binary Merkle tree over SHA-256 leaves.

Leaves and internal nodes use explicit domain prefixes to prevent ambiguous
leaf/node encodings. Inclusion proofs are validated structurally before hashing.
"""

import hashlib


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_leaf(data: bytes) -> bytes:
    return _h(b"\x00" + data)


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        if not isinstance(leaves, list) or not leaves:
            raise ValueError("MerkleTree requires at least one leaf")
        if any(not isinstance(leaf, bytes) for leaf in leaves):
            raise TypeError("all Merkle leaves must be bytes")
        self._leaf_count = len(leaves)
        n = 1 << (self._leaf_count - 1).bit_length()
        pad = _hash_leaf(b"")
        self._leaves = list(leaves) + [pad] * (n - self._leaf_count)
        self._n = n
        self._nodes = self._build()

    def _build(self) -> list[list[bytes]]:
        layer = [_hash_leaf(leaf) for leaf in self._leaves]
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
        return list(self._nodes[0][:self._leaf_count])

    def prove(self, index: int) -> list[dict]:
        """Return sibling hashes from leaf to root for an actual input leaf."""
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < self._leaf_count:
            raise IndexError("leaf index out of range")
        proof = []
        for layer in self._nodes[:-1]:
            sibling_idx = index ^ 1
            proof.append({
                "hash": layer[sibling_idx].hex(),
                "position": "right" if index % 2 == 0 else "left",
            })
            index //= 2
        return proof


def verify_proof(root: bytes, leaf: bytes, proof: list[dict], index: int) -> bool:
    """Verify an inclusion proof; malformed proofs return False."""
    if not isinstance(root, bytes) or len(root) != 32:
        return False
    if not isinstance(leaf, bytes) or not isinstance(proof, list):
        return False
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        return False
    if index >= (1 << len(proof)):
        return False

    current = _hash_leaf(leaf)
    for step in proof:
        if not isinstance(step, dict):
            return False
        sibling_hex = step.get("hash")
        position = step.get("position")
        expected_position = "right" if index % 2 == 0 else "left"
        if position != expected_position or not isinstance(sibling_hex, str) or len(sibling_hex) != 64:
            return False
        try:
            sibling = bytes.fromhex(sibling_hex)
        except ValueError:
            return False
        if len(sibling) != 32:
            return False
        current = (
            _hash_pair(current, sibling)
            if position == "right"
            else _hash_pair(sibling, current)
        )
        index //= 2
    return index == 0 and current == root
