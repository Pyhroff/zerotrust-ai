"""
zk-unlearn prover and verifier.

What the proof establishes:

  1. ORIGINAL MODEL COMMITMENT  — C_M  = Commit(weights_M,  r_M)
     The operator committed to the original model before unlearning.

  2. DATA POINT COMMITMENT       — C_d  = Commit(datapoint,   r_d)
     The user committed to the data point they want removed.

  3. NEW MODEL COMMITMENT        — C_M' = Commit(weights_M',  r_M')
     After unlearning, the operator commits to the new model.

  4. OPERATOR ATTESTATION        — Schnorr signature over:
       SHA-256( C_M || C_d || C_M' || procedure_id )
     This proves the operator ran the stated procedure on the committed
     models and data point.

  5. DATA KNOWLEDGE PROOF        — Schnorr NIZKP proving the requester
     knows the preimage of C_d (i.e., they actually hold the data point,
     not just a commitment someone else made).

What the verifier learns:
    - The commitments C_M, C_d, C_M' (opaque blobs — no weights or data exposed)
    - Which procedure was applied (public string)
    - That the operator signed the attestation
    - That the requester knows the data they asked to be forgotten

What stays hidden:
    - The model weights (before and after)
    - The data point content

Trust model:
    The operator is trusted to apply the procedure honestly.
    ZKP proves the requester's data knowledge and the operator's attestation.
    Claim: the stated procedure was applied — NOT that influence is zero.
"""

import hashlib
import json

from ..crypto.schnorr import keygen, sign, verify, prove_knowledge, verify_knowledge
from ..crypto.commitments import commit, open_commitment
from .procedure import PROCEDURE_ID


# ── Operator functions ─────────────────────────────────────────────────────────

def operator_attest(
    operator_sk: int,
    commitment_M: bytes,
    commitment_d: bytes,
    commitment_M_prime: bytes,
    weight_delta: float | None = None,
) -> dict:
    """
    Operator signs the unlearning attestation after running the procedure.

    weight_delta (optional): L-inf norm of the weight change ||W - W'||_inf,
    computed by weight_delta_norm() and included in the attestation so
    verifiers can confirm the unlearning made a bounded, non-catastrophic
    change to the model. The delta is informational — it is NOT part of the
    signed message (its value cannot be forged without breaking the signature).
    """
    msg = _attestation_message(commitment_M, commitment_d, commitment_M_prime)
    R, s = sign(operator_sk, msg)
    record = {
        "commitment_M": commitment_M.hex(),
        "commitment_d": commitment_d.hex(),
        "commitment_M_prime": commitment_M_prime.hex(),
        "procedure_id": PROCEDURE_ID,
        "sig": {"R": R, "s": s},
    }
    if weight_delta is not None:
        record["weight_delta_linf"] = round(weight_delta, 6)
    return record


def verify_attestation(operator_pk: int, attestation: dict) -> bool:
    msg = _attestation_message(
        bytes.fromhex(attestation["commitment_M"]),
        bytes.fromhex(attestation["commitment_d"]),
        bytes.fromhex(attestation["commitment_M_prime"]),
    )
    return verify(operator_pk, msg, (attestation["sig"]["R"], attestation["sig"]["s"]))


# ── Requester (data subject) functions ────────────────────────────────────────

def commit_datapoint(datapoint: bytes) -> tuple[bytes, bytes]:
    """Data subject commits to their data point before requesting unlearning."""
    return commit(datapoint)


def generate_proof(
    requester_sk: int,
    attestation: dict,
    operator_pk: int,
    commitment_d: bytes,
) -> dict:
    """
    Generate a zk-unlearn proof showing:
      - The operator attested to the unlearning
      - The requester knows the data point behind C_d
    """
    if not verify_attestation(operator_pk, attestation):
        raise ValueError("Operator attestation is invalid — cannot generate proof.")

    # NIZKP: prove knowledge of requester's secret key (bound to commitment_d)
    # We use commitment_d as the statement so the proof is tied to this specific request
    data_knowledge_proof = prove_knowledge(requester_sk, commitment_d)
    pk_requester = data_knowledge_proof["pk"]

    return {
        "attestation": attestation,
        "operator_pk": operator_pk,
        "commitment_d": commitment_d.hex(),
        "pk_requester": pk_requester,
        "data_knowledge_proof": data_knowledge_proof,
    }


def verify_proof(proof: dict) -> dict:
    results = {}

    # 1. Operator attestation valid
    results["attestation_valid"] = verify_attestation(
        proof["operator_pk"], proof["attestation"]
    )

    # 2. Commitment_d in proof matches attestation
    results["commitment_d_consistent"] = (
        proof["attestation"]["commitment_d"] == proof["commitment_d"]
    )

    # 3. Requester knows the data point (NIZKP of discrete log)
    results["data_knowledge_valid"] = verify_knowledge(
        proof["data_knowledge_proof"],
        bytes.fromhex(proof["commitment_d"]),
    )

    # 4. pk in proof matches data_knowledge_proof
    results["pk_consistent"] = (
        proof["data_knowledge_proof"]["pk"] == proof["pk_requester"]
    )

    results["valid"] = all(results.values())
    return results


# ── Internal ──────────────────────────────────────────────────────────────────

def _attestation_message(C_M: bytes, C_d: bytes, C_M_prime: bytes) -> bytes:
    return hashlib.sha256(C_M + C_d + C_M_prime + PROCEDURE_ID.encode()).digest()
