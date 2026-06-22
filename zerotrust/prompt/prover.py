"""
zk-prompt prover and verifier.

What the proof establishes (without revealing the user's real identity):

  1. IDENTITY PROOF   — Schnorr NIZKP: "I know the secret key behind pk_user"
                        Proves the person generating this proof is the same
                        pseudonym who received the operator-signed session.

  2. SESSION VALIDITY — The operator signature on (commitment, response, pk_user,
                        timestamp) is valid under the published operator public key.
                        This binds the response to a real operator interaction.

  3. PROMPT HIDING    — The prompt commitment is included but NOT opened here.
                        Optionally opened separately (whistleblower mode).

Trust model:
  The operator is trusted to sign only sessions it actually ran.
  ZKP proves the user pseudonymously owns a legitimate signed session.
  The operator cannot learn who the user is beyond pk_user.
"""

import hashlib
import json
import time

from ..crypto.schnorr import prove_knowledge, verify_knowledge, verify
from .operator import verify_session


def generate_proof(user_sk: int, session: dict, operator_pk: int) -> dict:
    """
    Generate a zero-knowledge proof that:
      - The prover knows the secret key for session["pk_user"]
      - The session carries a valid operator signature

    The proof statement binds to the session hash so it cannot be replayed
    against a different session.
    """
    session_hash = _session_hash(session)

    if not verify_session(operator_pk, session):
        raise ValueError("Operator signature on session is invalid — cannot prove.")

    # NIZKP: prove knowledge of sk s.t. h^sk = pk_user
    identity_proof = prove_knowledge(user_sk, session_hash)

    return {
        "session_hash": session_hash.hex(),
        "pk_user": session["pk_user"],
        "operator_pk": operator_pk,
        "prompt_commitment": session["prompt_commitment"],
        "response": session["response"],
        "timestamp": session["timestamp"],
        "operator_sig": session["sig"],
        "identity_proof": identity_proof,
    }


def verify_proof(proof: dict) -> dict:
    """
    Verify a zk-prompt proof.  Returns a result dict with per-check outcomes.
    """
    results = {}

    # 1. Identity: prover knows the secret key for pk_user
    session_hash = bytes.fromhex(proof["session_hash"])
    results["identity_valid"] = verify_knowledge(
        proof["identity_proof"], session_hash
    )
    results["pk_matches"] = (
        proof["identity_proof"]["pk"] == proof["pk_user"]
    )

    # 2. Session: operator signature is valid
    reconstructed_session = {
        "prompt_commitment": proof["prompt_commitment"],
        "response": proof["response"],
        "pk_user": proof["pk_user"],
        "timestamp": proof["timestamp"],
        "sig": proof["operator_sig"],
    }
    results["operator_sig_valid"] = verify_session(
        proof["operator_pk"], reconstructed_session
    )

    # 3. Session hash consistency
    results["session_hash_consistent"] = (
        _session_hash(reconstructed_session).hex() == proof["session_hash"]
    )

    results["valid"] = all(results.values())
    return results


def _session_hash(session: dict) -> bytes:
    blob = (
        session["prompt_commitment"]
        + session["response"]
        + str(session["pk_user"])
        + str(session["timestamp"])
    )
    return hashlib.sha256(blob.encode()).digest()
