"""
Schnorr signatures and non-interactive zero-knowledge proofs of discrete log.

Educational implementation over the RFC 3526 safe-prime subgroup. It is not
audited and should not be used as a production cryptographic library.
"""

import hashlib
import secrets

from .params import G, P, Q

H = pow(G, 2, P)
_DOMAIN = b"ZeroTrust-Schnorr-v1"


def keygen() -> tuple[int, int]:
    x = secrets.randbelow(Q - 1) + 1
    y = pow(H, x, P)
    if not validate_pubkey(y):
        raise RuntimeError("key generation produced an invalid public key")
    return x, y


def validate_pubkey(y: int) -> bool:
    """Return whether y is a non-identity member of the order-Q subgroup."""
    return (
        isinstance(y, int)
        and not isinstance(y, bool)
        and 1 < y < P
        and pow(y, Q, P) == 1
    )


def _valid_scalar(value: int, *, allow_zero: bool = False) -> bool:
    lower = 0 if allow_zero else 1
    return isinstance(value, int) and not isinstance(value, bool) and lower <= value < Q


def _valid_signature_inputs(pk: int, message: bytes, sig) -> bool:
    if not validate_pubkey(pk) or not isinstance(message, bytes):
        return False
    if not isinstance(sig, (tuple, list)) or len(sig) != 2:
        return False
    R, s = sig
    return (
        isinstance(R, int)
        and not isinstance(R, bool)
        and 1 < R < P
        and pow(R, Q, P) == 1
        and _valid_scalar(s, allow_zero=True)
    )


def _challenge(R: int, y: int, message: bytes) -> int:
    R_b = R.to_bytes(256, "big")
    y_b = y.to_bytes(256, "big")
    data = _DOMAIN + len(_DOMAIN).to_bytes(2, "big") + R_b + y_b + message
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % Q


def sign(sk: int, message: bytes) -> tuple[int, int]:
    if not _valid_scalar(sk) or not isinstance(message, bytes):
        raise ValueError("sk must be in [1, Q-1] and message must be bytes")
    y = pow(H, sk, P)
    k = secrets.randbelow(Q - 1) + 1
    R = pow(H, k, P)
    e = _challenge(R, y, message)
    s = (k - sk * e) % Q
    return R, s


def verify(pk: int, message: bytes, sig: tuple[int, int]) -> bool:
    """Verify safely: malformed/untrusted inputs return False, not exceptions."""
    try:
        if not _valid_signature_inputs(pk, message, sig):
            return False
        R, s = sig
        e = _challenge(R, pk, message)
        lhs = (pow(H, s, P) * pow(pk, e, P)) % P
        return lhs == R
    except (OverflowError, TypeError, ValueError):
        return False


def prove_knowledge(sk: int, statement: bytes) -> dict:
    """NIZKP: prove knowledge of x such that pk = h^x, without revealing x."""
    R, s = sign(sk, statement)
    return {"pk": pow(H, sk, P), "R": R, "s": s}


def verify_knowledge(proof: dict, statement: bytes) -> bool:
    if not isinstance(proof, dict):
        return False
    try:
        return verify(proof["pk"], statement, (proof["R"], proof["s"]))
    except (KeyError, TypeError):
        return False


def batch_verify(entries: list[tuple[int, bytes, tuple[int, int]]]) -> bool:
    """Batch-verify Schnorr signatures using fresh random coefficients."""
    if not isinstance(entries, (list, tuple)):
        return False
    if not entries:
        return True

    # Validate every untrusted item before arithmetic. This also prevents
    # malformed R/s values from reaching modular exponentiation.
    for entry in entries:
        if not isinstance(entry, (tuple, list)) or len(entry) != 3:
            return False
        pk, msg, sig = entry
        if not _valid_signature_inputs(pk, msg, sig):
            return False

    acc = 1
    for pk, msg, sig in entries:
        R, s = sig
        e = _challenge(R, pk, msg)
        r = secrets.randbelow(Q - 1) + 1
        term = (pow(H, s, P) * pow(pk, e, P) * pow(R, P - 2, P)) % P
        acc = (acc * pow(term, r, P)) % P
    return acc == 1


def proof_to_bytes(proof: dict) -> bytes:
    import json
    return json.dumps(proof).encode()


def proof_from_bytes(data: bytes) -> dict:
    import json
    return json.loads(data.decode())
