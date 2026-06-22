"""
Tiny 2-layer neural network with integer-quantized weights.

Architecture: input_dim → hidden(16, ReLU) → output(1, sigmoid)
Quantization: float32 weights scaled to int8 (range -127..127).

We use integer weights so commitments are over a finite, deterministic
byte representation — essential for ZKP (can't commit to floats reliably).
"""

import hashlib
import json
import secrets

import numpy as np


SCALE = 127.0  # float ↔ int8 scale factor


class TinyNet:
    def __init__(self, input_dim: int = 4, hidden: int = 16):
        rng = np.random.default_rng(42)
        self.W1 = rng.normal(0, 0.5, (hidden, input_dim)).astype(np.float32)
        self.b1 = np.zeros(hidden, dtype=np.float32)
        self.W2 = rng.normal(0, 0.5, (1, hidden)).astype(np.float32)
        self.b2 = np.zeros(1, dtype=np.float32)

    # ── forward pass ──────────────────────────────────────────────────────────

    def forward(self, x: np.ndarray) -> np.ndarray:
        h = np.maximum(0, x @ self.W1.T + self.b1)
        return _sigmoid(h @ self.W2.T + self.b2)

    def predict(self, x: np.ndarray) -> int:
        return int(self.forward(x)[0] > 0.5)

    # ── training (mini-batch SGD) ──────────────────────────────────────────────

    def train(self, X: np.ndarray, y: np.ndarray, epochs: int = 200, lr: float = 0.1):
        for _ in range(epochs):
            h_pre = X @ self.W1.T + self.b1
            h = np.maximum(0, h_pre)
            out = _sigmoid(h @ self.W2.T + self.b2)

            loss_grad = out - y.reshape(-1, 1)

            dW2 = loss_grad.T @ h / len(X)
            db2 = loss_grad.mean(axis=0)

            dh = loss_grad @ self.W2
            dh_pre = dh * (h_pre > 0).astype(np.float32)

            dW1 = dh_pre.T @ X / len(X)
            db1 = dh_pre.mean(axis=0)

            self.W1 -= lr * dW1
            self.b1 -= lr * db1
            self.W2 -= lr * dW2
            self.b2 -= lr * db2

    # ── quantization & commitment ──────────────────────────────────────────────

    def quantize(self) -> dict:
        """Return int8-quantized weights as a dict of lists."""
        return {
            "W1": _quant(self.W1).tolist(),
            "b1": _quant(self.b1).tolist(),
            "W2": _quant(self.W2).tolist(),
            "b2": _quant(self.b2).tolist(),
        }

    def weight_bytes(self) -> bytes:
        """Canonical byte representation of quantized weights for commitment."""
        q = self.quantize()
        return json.dumps(q, sort_keys=True, separators=(",", ":")).encode()

    def commit_weights(self) -> tuple[bytes, bytes]:
        """Returns (commitment, randomness)."""
        from ..crypto.commitments import commit
        return commit(self.weight_bytes())

    def load_quantized(self, q: dict):
        self.W1 = _dequant(np.array(q["W1"], dtype=np.int8))
        self.b1 = _dequant(np.array(q["b1"], dtype=np.int8))
        self.W2 = _dequant(np.array(q["W2"], dtype=np.int8))
        self.b2 = _dequant(np.array(q["b2"], dtype=np.int8))

    def clone(self) -> "TinyNet":
        other = TinyNet.__new__(TinyNet)
        other.W1 = self.W1.copy()
        other.b1 = self.b1.copy()
        other.W2 = self.W2.copy()
        other.b2 = self.b2.copy()
        return other


def _sigmoid(x):
    return 1 / (1 + np.exp(-np.clip(x, -30, 30)))


def _quant(w: np.ndarray) -> np.ndarray:
    return np.clip(np.round(w * SCALE), -127, 127).astype(np.int8)


def _dequant(w: np.ndarray) -> np.ndarray:
    return w.astype(np.float32) / SCALE
