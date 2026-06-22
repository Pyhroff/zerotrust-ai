"""
Operator side of zk-prompt.

The operator (AI service) holds a Schnorr keypair.  For every
(prompt, response) pair it serves, it signs a session record so that
the user later has cryptographic evidence the exchange happened.

Session record signed:
  SHA-256( prompt_commitment || response_bytes || pk_user || timestamp_bytes )

Signing this record does NOT reveal the prompt to anyone who only sees the
signature — the prompt commitment is hiding.  To selectively reveal the prompt
(whistleblower mode), the user opens the commitment separately.
"""

import hashlib
import json
import time

from ..crypto.schnorr import keygen, sign, verify


def setup() -> dict:
    sk, pk = keygen()
    return {"sk": sk, "pk": pk}


def _session_message(
    prompt_commitment: bytes,
    response: str,
    pk_user: int,
    timestamp: int,
) -> bytes:
    return hashlib.sha256(
        prompt_commitment
        + response.encode()
        + pk_user.to_bytes(256, "big")
        + timestamp.to_bytes(8, "big")
    ).digest()


def sign_session(
    operator_sk: int,
    prompt_commitment: bytes,
    response: str,
    pk_user: int,
) -> dict:
    """
    Called by the operator after generating a response.
    Returns a signed session record the user stores locally.
    """
    ts = int(time.time())
    msg = _session_message(prompt_commitment, response, pk_user, ts)
    R, s = sign(operator_sk, msg)
    return {
        "prompt_commitment": prompt_commitment.hex(),
        "response": response,
        "pk_user": pk_user,
        "timestamp": ts,
        "sig": {"R": R, "s": s},
    }


def verify_session(operator_pk: int, session: dict) -> bool:
    prompt_commitment = bytes.fromhex(session["prompt_commitment"])
    msg = _session_message(
        prompt_commitment,
        session["response"],
        session["pk_user"],
        session["timestamp"],
    )
    R = session["sig"]["R"]
    s = session["sig"]["s"]
    return verify(operator_pk, msg, (R, s))
