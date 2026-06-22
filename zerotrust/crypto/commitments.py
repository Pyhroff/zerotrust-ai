"""
Hiding + binding hash commitments.

  Commit(value, randomness) = SHA-256(value || randomness)

Hiding:  without randomness, commitment reveals nothing about value.
Binding: once committed, prover cannot open to a different value.
"""

import hashlib
import hmac
import secrets


def commit(value: bytes) -> tuple[bytes, bytes]:
    """Returns (commitment, randomness). Keep randomness secret until reveal."""
    r = secrets.token_bytes(32)
    c = hashlib.sha256(value + r).digest()
    return c, r


def open_commitment(commitment: bytes, value: bytes, randomness: bytes) -> bool:
    # hmac.compare_digest prevents timing oracles that could leak the commitment
    # preimage by measuring how long the equality check takes.
    candidate = hashlib.sha256(value + randomness).digest()
    return hmac.compare_digest(commitment, candidate)


def hash_value(value: bytes) -> bytes:
    """Plain SHA-256 (non-hiding). Use when privacy isn't needed."""
    return hashlib.sha256(value).digest()
