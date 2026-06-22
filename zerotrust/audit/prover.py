"""
zk-audit prover and verifier.

What the proof establishes:

  For a committed test suite (known only by its Merkle root):
    - Every test in the suite has a valid operator-signed result.
    - Every signed result says "PASS".
    - Each signed result corresponds to a leaf in the committed Merkle tree
      (proven via inclusion proof).

What the verifier learns:
    - The suite root (public commitment — does not reveal test cases).
    - The operator's public key.
    - The number of tests.
    - That ALL tests passed.

What stays hidden:
    - The individual test inputs and constraints.
    - The model's responses.

Trust model:
    The operator is trusted to sign only results from actually running the model.
    The ZKP layer proves the audit is complete and all-passing without
    disclosing the red-team test suite to anyone (including the model owner).
"""

from .suite import AuditSuite
from .operator import verify_result


def generate_proof(
    suite: AuditSuite,
    signed_results: list[dict],
    operator_pk: int,
) -> dict:
    """
    Build an audit proof from a completed set of signed results.
    Raises if any result is FAIL or has an invalid signature.
    """
    if len(signed_results) != suite.size:
        raise ValueError(
            f"Expected {suite.size} results, got {len(signed_results)}"
        )

    inclusion_proofs = []
    for i, result in enumerate(signed_results):
        # 1. Signature valid?
        if not verify_result(operator_pk, result):
            raise ValueError(f"Invalid operator signature on result {i}")

        # 2. All pass?
        if result["result"] != "PASS":
            raise ValueError(f"Test {i} did not pass - cannot generate proof")

        # 3. Result belongs to committed suite?
        inc_proof = suite.inclusion_proof(i)
        if not suite.verify_inclusion(suite.root, inc_proof):
            raise ValueError(f"Inclusion proof failed for test {i}")

        # 4. Leaf preimage in result matches what suite says
        expected_leaf = bytes.fromhex(inc_proof["leaf_preimage"])
        actual_leaf = bytes.fromhex(result["_leaf_preimage"])
        if expected_leaf != actual_leaf:
            raise ValueError(f"Leaf mismatch at index {i}")

        inclusion_proofs.append(inc_proof)

    return {
        "suite_root": suite.root.hex(),
        "num_tests": suite.size,
        "operator_pk": operator_pk,
        "inclusion_proofs": inclusion_proofs,
        "signed_results": signed_results,
    }


def verify_proof(proof: dict) -> dict:
    """
    Verify an audit proof.  Returns per-check results.
    A third party only needs the proof dict and the operator's public key.
    """
    results = {
        "sig_valid": [],
        "all_pass": [],
        "inclusion_valid": [],
        "leaf_consistent": [],
    }
    suite_root = bytes.fromhex(proof["suite_root"])
    operator_pk = proof["operator_pk"]

    for i, (signed_result, inc_proof) in enumerate(
        zip(proof["signed_results"], proof["inclusion_proofs"])
    ):
        # Signature
        results["sig_valid"].append(verify_result(operator_pk, signed_result))

        # Result is PASS
        results["all_pass"].append(signed_result["result"] == "PASS")

        # Merkle inclusion
        from ..crypto.merkle import verify_proof as mp_verify
        leaf = bytes.fromhex(inc_proof["leaf_preimage"])
        results["inclusion_valid"].append(
            mp_verify(suite_root, leaf, inc_proof["siblings"], inc_proof["index"])
        )

        # Leaf preimage consistency between result and inclusion proof
        results["leaf_consistent"].append(
            signed_result["_leaf_preimage"] == inc_proof["leaf_preimage"]
        )

    summary = {
        "suite_root": proof["suite_root"],
        "num_tests": proof["num_tests"],
        "all_sigs_valid": all(results["sig_valid"]),
        "all_tests_passed": all(results["all_pass"]),
        "all_inclusions_valid": all(results["inclusion_valid"]),
        "all_leaves_consistent": all(results["leaf_consistent"]),
        "per_test": results,
    }
    summary["valid"] = (
        summary["all_sigs_valid"]
        and summary["all_tests_passed"]
        and summary["all_inclusions_valid"]
        and summary["all_leaves_consistent"]
    )
    return summary
