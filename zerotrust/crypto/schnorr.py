"""
Schnorr signatures and non-interactive zero-knowledge proofs of discrete log.

Scheme:
  - Group: prime-order subgroup of Z*_P of order Q (RFC 3526 2048-bit)
  - Generator h = G^2 mod P  (squaring maps G into the Q-order subgroup)
  - Private key x ∈ [1, Q-1]
  - Public key  y = h^x mod P

Signing (= Fiat-Shamir NIZKP of knowledge of x):
  1. Pick random nonce k ∈ [1, Q-1]
  2. Commitment R = h^k mod P
  3. Challenge  e = H(R || y || message) mod Q
  4. Response   s = (k - x*e) mod Q
  Signature: (R, s)

Verification:
  e = H(R || y || message) mod Q
  Check: h^s * y^e ≡ R (mod P)
"""

import hashlib
import secrets

from .params import G, P, Q

H = pow(G, 2, P)  # generator of prime-order subgroup


def keygen() -> tuple[int, int]:
    x = secrets.randbelow(Q - 1) + 1
    y = pow(H, x, P)
    assert validate_pubkey(y), "keygen produced key outside prime-order subgroup"
    return x, y


def validate_pubkey(y: int) -> bool:
    """Check y is in the prime-order subgroup: y != 1 and y^Q == 1 (mod P)."""
    return y != 1 and pow(y, Q, P) == 1


# Domain separation label prevents cross-protocol attacks where a proof
# generated in one context is replayed as valid in another.
_DOMAIN = b"ZeroTrust-Schnorr-v1"


def _challenge(R: int, y: int, message: bytes) -> int:
    R_b = R.to_bytes(256, "big")
    y_b = y.to_bytes(256, "big")
    # Hash: domain || len(domain) || R || y || message
    data = (
        _DOMAIN
        + len(_DOMAIN).to_bytes(2, "big")
        + R_b
        + y_b
        + message
    )
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % Q


def sign(sk: int, message: bytes) -> tuple[int, int]:
    y = pow(H, sk, P)
    k = secrets.randbelow(Q - 1) + 1
    R = pow(H, k, P)
    e = _challenge(R, y, message)
    s = (k - sk * e) % Q
    return (R, s)


def verify(pk: int, message: bytes, sig: tuple[int, int]) -> bool:
    if not validate_pubkey(pk):
        return False
    y = pk
    R, s = sig
    e = _challenge(R, y, message)
    lhs = (pow(H, s, P) * pow(y, e, P)) % P
    return lhs == R


def prove_knowledge(sk: int, statement: bytes) -> dict:
    """NIZKP: prove knowledge of x s.t. y = h^x, without revealing x."""
    y = pow(H, sk, P)
    R, s = sign(sk, statement)
    return {"pk": y, "R": R, "s": s}


def verify_knowledge(proof: dict, statement: bytes) -> bool:
    return verify(proof["pk"], statement, (proof["R"], proof["s"]))


def proof_to_bytes(proof: dict) -> bytes:
    import json
    return json.dumps({k: v for k, v in proof.items()}).encode()


def proof_from_bytes(data: bytes) -> dict:
    import json
    return json.loads(data.decode())
