# ZeroTrust AI

**A cryptographic protocol framework for AI accountability, built on a from-scratch Schnorr ZKP implementation.**

Three governance protocols — anonymous prompt evidence, hidden-suite safety auditing, and verifiable machine unlearning — each with a working cryptographic layer and a clean interface for connecting a real model.

> **Honest scope:** The ZKP layer is fully implemented and runs real proofs. The AI slot in each demo is a stub (hardcoded responses / a toy numpy net). The design is production-shaped; the model integration is not yet wired up.

---

## What's actually here

### The cryptographic layer — implemented from scratch

`zerotrust/crypto/` contains no external crypto dependencies. Everything is built over Python stdlib (`hashlib`, `hmac`, `secrets`) on the RFC 3526 2048-bit safe prime group:

**`schnorr.py`** — Schnorr signature scheme and NIZKP

- Keygen in the prime-order subgroup of order $q = (p-1)/2$, generator $h = g^2 \bmod p$
- Sign / Verify via Fiat-Shamir heuristic (non-interactive)
- `prove_knowledge(sk, statement)` — NIZKP of discrete log: proves knowledge of $x$ s.t. $y = h^x \bmod p$ without revealing $x$
- `batch_verify([(pk, msg, sig), ...])` — verifies $n$ signatures via random linear combination in one pass, saving $n-1$ exponentiations
- Domain separation label `ZeroTrust-Schnorr-v1` prefixed to all challenge hashes
- Subgroup membership check on every public key: $y \neq 1$ and $y^q \equiv 1 \pmod{p}$

**`commitments.py`** — SHA-256 hiding commitments

```
Commit(value) = SHA-256(value || r),  r ←_R {0,1}^256
```

`open_commitment` uses `hmac.compare_digest` — constant-time comparison prevents timing oracles on the commitment opening check.

**`merkle.py`** — Binary Merkle tree with inclusion proofs

Build, prove membership at index $i$, verify inclusion against root. Used in `zk-audit` to commit to a test suite without revealing individual tests.

---

### The protocols — three governance designs

Each protocol is a full design: the trust model is explicit, what gets proven is specified, what stays hidden is stated. The demos run end-to-end in a single process (operator + user + verifier all local).

#### `zk-prompt` — Anonymous AI Evidence

**The problem.** A user gets an AI response they want to prove is authentic — maybe for a whistleblower claim, a regulator complaint, or a legal dispute. A screenshot is forgeable. Revealing their identity may expose them.

**What's built.** Operator signs every session record:

```
σ = Schnorr.Sign(sk_op, SHA-256(prompt_commitment || response || pk_user || timestamp || nonce))
```

The prompt is hidden behind a SHA-256 commitment. The user's identity is an anonymous Schnorr keypair. The ZKP proves the user knows the secret key behind `pk_user` — i.e., they are the pseudonym that received this signed session — without revealing who they are.

**What the proof actually proves (precisely):**
- Knowledge of discrete log: prover knows $sk$ s.t. $pk_{user} = h^{sk}$
- Operator signature on the session record is valid under published $pk_{op}$
- The proof is bound to this session via a hash — cannot be replayed elsewhere

**What the stub looks like.** In the demo, the model response is a hardcoded Python string. In production, this would be the output of a real inference call, with the operator signing before returning the response.

```python
# demo stub
model_response = "I can't provide instructions for exploiting this vulnerability..."

# production hookup would look like:
response = model.generate(prompt)
session = sign_session(op_sk, commit(prompt), response, pk_user)
```

---

#### `zk-audit` — Hidden-Suite Safety Certification

**The problem.** A safety team has a red-team test suite they don't want to disclose — revealing it lets the model owner overfit to it; publishing it creates an attack playbook. They want to certify "this model passed all our tests" without showing the tests.

**What's built.** The auditor commits to the suite as a Merkle tree of leaf hashes:

```
leaf_i = SHA-256(input_i || 0x00 || constraint_i)
root   = MerkleRoot(leaf_1, ..., leaf_n)
```

The operator signs each result, binding the suite root into the signature:

```
σ_i = Schnorr.Sign(sk_op, SHA-256(root || i || leaf_i || result_i))
```

The proof bundles `(σ_i, result_i, MerkleProof_i)` for every test. Verification checks all signatures (via batch verify), all results are PASS, and all Merkle paths open against the committed root.

**What the stub looks like.** Constraint evaluation is rule-based string matching (`must_refuse`, `must_contain:X`, `must_not_contain:X`). In production this would call a real safety classifier or human review endpoint. The protocol is model-agnostic — `run_suite(operator_sk, suite, model_fn)` accepts any `(str) -> str` callable.

---

#### `zk-unlearn` — Verifiable Machine Unlearning

**The problem.** Under GDPR Art. 17, operators must remove data from trained models on request. Currently they just say they did it. A cryptographic proof would let them demonstrate compliance without disclosing model weights or remaining training data.

**What's built.** Commitments to the original model, data point, and unlearned model:

```
C_M  = SHA-256(quantized_weights_before || r_M)
C_d  = SHA-256(datapoint_bytes         || r_d)
C_M' = SHA-256(quantized_weights_after || r_M')
```

Operator attestation binds the procedure ID into the signature:

```
σ = Schnorr.Sign(sk_op, SHA-256(C_M || C_d || C_M' || "GAU-v1:..."))
```

The requester generates a NIZKP proving they know the data point behind $C_d$ — i.e., they are the person whose data was removed, not a third party claiming credit. The weight delta $\|\theta - \theta'\|_\infty$ is included as a sanity observable.

**What the stub looks like.** The "AI" here is a real 2-layer numpy neural net (4 inputs → 16 hidden → 1 output, int8-quantized weights, trained on 50 synthetic points). Gradient ascent unlearning actually runs and modifies the weights. It's a toy model but the unlearning procedure and commitment flow are the same as they would be for a larger model — just swap in your weight serializer.

**Scope of the claim (stated openly).** This proof establishes the procedure was executed on the committed weights. It does not prove the data point has zero influence in the resulting model — that is an open problem. See [Thudi et al., 2022](https://arxiv.org/abs/2205.02284).

---

### `tamper-demo` — Soundness Verification

Generates a valid `zk-prompt` proof then attempts 8 systematic tampering attacks — swapping the response, flipping bits in `pk_user`, zeroing the signature scalar, corrupting the session hash, mutating the nonce, and more. Every modification must be detected by `verify_proof()`.

```
python main.py tamper-demo

  Base proof:  VALID
  Tamper: response swapped          -> REJECTED
  Tamper: pk_user flipped           -> REJECTED
  Tamper: operator_pk flipped       -> REJECTED
  Tamper: sig R incremented         -> REJECTED
  Tamper: sig s zeroed              -> REJECTED
  Tamper: identity proof R flipped  -> REJECTED
  Tamper: session hash corrupted    -> REJECTED
  Tamper: nonce mutated             -> REJECTED

  All tampering attempts rejected -- proof is sound
```

---

## Trust model

The operator holds a Schnorr keypair and signs their outputs. This is an **operator-participation model** — the same trust assumption as TLS. The ZKP layer provides:

- **Privacy** — user identity and prompt content are hidden from verifiers
- **Completeness** — auditor cannot exclude failing tests without changing the committed root
- **Non-repudiation** — operator cannot deny signing a session record without breaking DLOG

What it does not provide: a guarantee the operator signed honestly. That requires external accountability (transparency logs, multi-party signing, regulatory audits). This is the same limitation as any PKI.

---

## Security decisions

| Decision | Why |
|----------|-----|
| Schnorr over ECDSA | Batch verification + linear aggregation; tighter ROM reduction |
| Safe prime group, not EC | Stdlib-only; auditable without curve arithmetic knowledge |
| SHA-256 commitments, not Pedersen | Simpler; no trusted setup; swap to Pedersen when moving to a zk-SNARK circuit |
| Fiat-Shamir domain label | Prevents cross-protocol proof transplanting |
| Per-session nonce | Prevents signature replay on repeated identical queries |
| `hmac.compare_digest` | Constant-time; closes timing oracle on commitment opening |
| Subgroup membership check | Prevents small-subgroup attacks on public keys |

---

## Installation

```bash
git clone https://github.com/Pyhroff/zerotrust-ai
cd zerotrust-ai
pip install -r requirements.txt   # click, rich, numpy
python main.py prompt demo
python main.py audit demo
python main.py unlearn demo
python main.py tamper-demo
```

Python 3.11+. No external crypto dependencies.

---

## Connecting a real model

Each module exposes a clean interface. To wire in a real model:

**zk-prompt**
```python
from zerotrust.prompt import operator_setup, sign_session, new_identity, prepare_prompt

op = operator_setup()   # do once, publish op["pk"]
user = new_identity()

_, commitment, randomness = prepare_prompt(user_query)
response = your_model.generate(user_query)          # your model here
session = sign_session(op["sk"], commitment, response, user["pk"])
```

**zk-audit**
```python
from zerotrust.audit import AuditSuite, operator_setup, run_suite, generate_proof

suite = AuditSuite(your_test_cases)
op = operator_setup()
signed_results = run_suite(op["sk"], suite, your_model.generate)  # any (str)->str
proof = generate_proof(suite, signed_results, op["pk"])
```

**zk-unlearn**
```python
from zerotrust.unlearn import commit_datapoint, operator_attest, generate_proof
from zerotrust.unlearn.procedure import unlearn, weight_delta_norm

C_M, _ = your_model.commit_weights()
C_d, _ = commit_datapoint(datapoint_bytes)
new_model = unlearn(your_model, forget_point, forget_label, retain_X, retain_y)
delta = weight_delta_norm(your_model, new_model)
C_M_prime, _ = new_model.commit_weights()
attestation = operator_attest(op_sk, C_M, C_d, C_M_prime, weight_delta=delta)
```

---

## What's next

- [ ] Replace SHA-256 commitments with Pedersen vector commitments (enables arithmetic proofs over committed weights)
- [ ] Wire up a real LLM endpoint for `zk-prompt` and `zk-audit` demos
- [ ] Move to Ristretto255 for ~8x faster group operations
- [ ] Publish session commitments to a transparency log to close the operator-trust gap
- [ ] zkSNARK circuit for the GAU forward pass (full verifiable unlearning)

---

## References

1. Schnorr, C. P. (1991). *Efficient signature generation by smart cards.* Journal of Cryptology.
2. Bellare, M. & Rogaway, P. (1993). *Random oracles are practical.* CCS '93.
3. Thudi, A. et al. (2022). *Unrolling SGD: Understanding Factors Influencing Machine Unlearning.* EuroS&P.
4. Nguyen, T. T. et al. (2022). *A Survey of Machine Unlearning.* arXiv:2209.02299.
5. RFC 3526 — *MODP Diffie-Hellman groups for Internet Key Exchange.*
6. EU AI Act (2024). Art. 9 (risk management), Art. 72 (fundamental rights impact assessment).

---

## License

MIT — see [LICENSE](LICENSE).
