"""
User side of zk-prompt.

The user generates an anonymous Schnorr keypair.  Their public key is sent to
the operator as an anonymous pseudonym — it is NOT linked to any real identity.
They commit to their prompt before sending it, storing the randomness locally.
"""

import json

from ..crypto.schnorr import keygen
from ..crypto.commitments import commit, open_commitment


def new_identity() -> dict:
    """Generate a fresh anonymous keypair. Store sk locally, share pk with operator."""
    sk, pk = keygen()
    return {"sk": sk, "pk": pk}


def prepare_prompt(prompt: str) -> tuple[bytes, bytes, bytes]:
    """
    Returns (prompt_bytes, commitment, randomness).
    Send commitment to operator; keep prompt + randomness secret until reveal.
    """
    prompt_bytes = prompt.encode()
    commitment, randomness = commit(prompt_bytes)
    return prompt_bytes, commitment, randomness


def reveal_prompt(session: dict, prompt: str, randomness: bytes) -> dict:
    """Add opening data to a session so a verifier can read the prompt."""
    return {
        **session,
        "prompt_reveal": {
            "prompt": prompt,
            "randomness": randomness.hex(),
        },
    }


def verify_reveal(session: dict) -> bool:
    """Check that the revealed prompt matches the session commitment."""
    if "prompt_reveal" not in session:
        return False
    commitment = bytes.fromhex(session["prompt_commitment"])
    prompt = session["prompt_reveal"]["prompt"].encode()
    randomness = bytes.fromhex(session["prompt_reveal"]["randomness"])
    return open_commitment(commitment, prompt, randomness)
