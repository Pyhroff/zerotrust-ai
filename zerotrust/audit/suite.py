"""
Test suite management for zk-audit.

An audit suite is a list of test cases, each with:
  - input:    the prompt / input fed to the model
  - expected: behavioural constraint (e.g. "must refuse", "must not contain X")

The auditor commits to the suite via a Merkle tree BEFORE sharing it with
the operator.  The Merkle root is the public commitment; the leaves are kept
secret until (optionally) revealed after auditing.

Leaf preimage = SHA-256( input || "\x00" || constraint )
This prevents length-extension and separates the two fields unambiguously.
"""

import hashlib
import json

from ..crypto.merkle import MerkleTree, verify_proof


def _leaf_preimage(test: dict) -> bytes:
    return (test["input"] + "\x00" + test["constraint"]).encode()


class AuditSuite:
    def __init__(self, tests: list[dict]):
        """
        tests: list of {"input": str, "constraint": str}
        """
        for t in tests:
            if "input" not in t or "constraint" not in t:
                raise ValueError("Each test needs 'input' and 'constraint' keys")
        self._tests = tests
        self._tree = MerkleTree([_leaf_preimage(t) for t in tests])

    @property
    def root(self) -> bytes:
        return self._tree.root

    @property
    def size(self) -> int:
        return len(self._tests)

    def get_test(self, index: int) -> dict:
        return self._tests[index]

    def inclusion_proof(self, index: int) -> dict:
        """Proof that test[index] is in the committed suite."""
        return {
            "index": index,
            "leaf_preimage": _leaf_preimage(self._tests[index]).hex(),
            "siblings": self._tree.prove(index),
        }

    def verify_inclusion(self, root: bytes, proof: dict) -> bool:
        leaf = bytes.fromhex(proof["leaf_preimage"])
        return verify_proof(root, leaf, proof["siblings"], proof["index"])

    def to_dict(self) -> dict:
        return {
            "tests": self._tests,
            "root": self.root.hex(),
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditSuite":
        suite = cls(d["tests"])
        assert suite.root.hex() == d["root"], "Suite root mismatch — file tampered?"
        return suite
