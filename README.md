# ZeroTrust AI

**Cryptographic accountability for AI systems using zero-knowledge proofs.**

ZeroTrust AI is a Python toolkit that lets you make verifiable claims about AI interactions — without revealing sensitive data. It implements three ZKP-backed primitives that address real gaps in AI governance: anonymous evidence of AI outputs, auditable safety certifications, and verifiable machine unlearning.

---

## The problem

AI systems today ask for trust on faith:

- "Our model passed safety evaluations." — *Which evaluations? Show us.*
- "We deleted your data from our model." — *Prove it.*
- "This AI said something harmful to me." — *Who are you? Prove the AI said it.*

ZKP lets you answer all three without revealing what you want to keep private.

---

## Modules

### `zk-prompt` — Anonymous AI Evidence

A user proves they received a specific AI response **without revealing their identity or the prompt**.

Use cases:
- Whistleblowers proving an AI gave harmful advice, anonymously
- Journalists verifying AI outputs without exposing sources
- Users proving AI model behaviour to regulators

```
python main.py prompt demo
python main.py prompt demo --reveal        # whistleblower mode: also opens the prompt
python main.py prompt demo --output proof.json
```

### `zk-audit` — Hidden-Suite Safety Certification

An auditor proves a model passed every test in a safety suite **without revealing what the tests were**.

Use cases:
- EU AI Act compliance certificates that don't expose red-team test cases
- Third-party safety audits where the test suite is a trade secret
- Continuous safety monitoring with cryptographic receipts

```
python main.py audit demo
python main.py audit demo --output audit_proof.json
```

### `zk-unlearn` — Verifiable Machine Unlearning

An operator proves a specific data point was removed from a model using a public procedure **without revealing the model weights or the data**.

Use cases:
- GDPR "right to be forgotten" with cryptographic evidence
- Demonstrating compliance to regulators without model disclosure
- Auditable data deletion in federated learning systems

```
python main.py unlearn demo
python main.py unlearn demo --output unlearn_proof.json
```

### `tamper-demo` — Soundness Check

Generates a valid proof and attempts 8 systematic tampering attacks. Every modification must be detected.

```
python main.py tamper-demo
```

---

## Architecture

```
zerotrust/
├── crypto/
│   ├── params.py         RFC 3526 2048-bit safe prime group parameters
│   ├── schnorr.py        Schnorr signatures + NIZKP + batch verification
│   ├── commitments.py    Hiding + binding SHA-256 commitments
│   └── merkle.py         Binary Merkle tree (build, prove, verify)
├── prompt/
│   ├── operator.py       Operator keypair, session signing with nonce
│   ├── user.py           Anonymous user identity, prompt commitment
│   └── prover.py         ZK proof of prompt ownership + verification
├── audit/
│   ├── suite.py          Test suite + Merkle tree commitment
│   ├── operator.py       Per-test signing, batch suite runner
│   └── prover.py         ZK proof of all-pass audit + batch verification
└── unlearn/
    ├── model.py           Tiny 2-layer quantized neural net (numpy)
    ├── procedure.py       Gradient Ascent Unlearning (GAU-v1)
    └── prover.py          Operator attestation + data knowledge proof
```

---

## Cryptographic Primitives

| Primitive | Implementation |
|-----------|---------------|
| Group | Prime-order subgroup of Z\*\_P, order Q (RFC 3526 2048-bit MODP) |
| Generator | h = G² mod P (squaring maps into Q-order subgroup) |
| Signatures | Schnorr (Fiat-Shamir heuristic, non-interactive) |
| Domain separation | `ZeroTrust-Schnorr-v1` label prefixed to all challenge hashes |
| Commitments | SHA-256(value \|\| randomness) — hiding + computationally binding |
| Merkle tree | Binary tree over SHA-256 leaf hashes |
| Batch verification | Random linear combination of n signature equations |
| Timing safety | `hmac.compare_digest` for all equality checks on secrets |

All cryptographic code uses Python stdlib only (`hashlib`, `hmac`, `secrets`). No external crypto dependencies.

---

## Trust Model

ZeroTrust AI uses an **operator-participation model**: the AI service signs its own outputs. This is the same trust assumption as TLS — you trust the certificate authority (here, the operator's signing key) and ZKP handles everything above that.

Concretely:

- `zk-prompt`: the operator signs `H(commitment || response || pk_user || timestamp || nonce)`. ZKP proves anonymous ownership of that signature.
- `zk-audit`: the operator signs each `H(suite_root || index || leaf || result)`. ZKP proves all N signed results are PASS and belong to the committed Merkle tree.
- `zk-unlearn`: the operator signs `H(C_M || C_d || C_M' || procedure_id)`. ZKP proves the requester knows the preimage of C_d (owns the data they asked to forget).

If the operator cheats (signs false results), the trust breaks — but this is also true of any TLS deployment. The ZKP layer then provides privacy and completeness guarantees on top.

---

## Limitations

**zk-unlearn** proves the *procedure was followed*, not that the data point has zero influence. Perfect influence removal is an open research problem in machine unlearning. The GAU procedure (gradient ascent + retain fine-tuning) is an approximation; the ZKP makes the approximation transparent and verifiable.

This codebase is a research prototype. The 2048-bit group provides ~112-bit security, which is appropriate for demonstration. Production deployments should use 3072-bit groups or elliptic curve groups (e.g., Ristretto255).

---

## Installation

```bash
pip install -r requirements.txt
```

Requirements: `click`, `rich`, `numpy`. Python 3.11+.

---

## Related Work

- [EZKL](https://github.com/zkonduit/ezkl) — ZK proofs for ONNX model inference (production zkML)
- [Modulus Labs](https://www.modulus.xyz/) — on-chain verifiable inference
- [Schnorr (original)](https://link.springer.com/article/10.1007/BF00196725) — C. P. Schnorr, 1991
- [Machine Unlearning Survey](https://arxiv.org/abs/2209.02299) — Nguyen et al., 2022
- [EU AI Act](https://artificialintelligenceact.eu/) — the regulatory context for zk-audit

---

## License

MIT — see [LICENSE](LICENSE).
