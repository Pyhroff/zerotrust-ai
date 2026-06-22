"""
Gradient Ascent Unlearning (GAU) — the public unlearning procedure.

The procedure ID is a fixed string that both parties refer to.  Including it
in the operator's signed attestation means the signature is only valid for
this specific procedure applied to these specific committed weights.

GAU intuition:
  Normal training minimises loss on a data point (gradient descent).
  Unlearning maximises loss on it (gradient ascent) — nudging the model to
  "forget" the point by making it perform worse on it specifically.
  After GAU, a fine-tuning step on the remaining data restores general accuracy.

Limitations (stated openly in the README):
  GAU is an approximation.  It does not guarantee perfect forgetting.
  The ZKP here proves the *procedure* was followed, not that the data point
  has zero influence — that is an open research problem.
"""

import numpy as np

PROCEDURE_ID = "GAU-v1:ascent_steps=50,lr=0.05,finetune_steps=100,finetune_lr=0.05"


def unlearn(
    model,  # TinyNet — modified in-place, returns clone
    forget_point: np.ndarray,
    forget_label: np.ndarray,
    retain_X: np.ndarray,
    retain_y: np.ndarray,
) -> object:
    """
    Apply GAU to model, returning a new model with the forget_point unlearned.
    The original model is not modified.
    """
    m = model.clone()

    # Phase 1: gradient ascent on forget point (maximise loss = forget)
    for _ in range(50):
        x = forget_point.reshape(1, -1)
        yf = forget_label.reshape(1, -1)

        h_pre = x @ m.W1.T + m.b1
        h = np.maximum(0, h_pre)
        out = _sigmoid(h @ m.W2.T + m.b2)

        # Negate the gradient (ascent = move AWAY from correct prediction)
        loss_grad = -(out - yf)

        dW2 = loss_grad.T @ h
        db2 = loss_grad[0]
        dh = loss_grad @ m.W2
        dh_pre = dh * (h_pre > 0).astype(np.float32)
        dW1 = dh_pre.T @ x
        db1 = dh_pre[0]

        m.W1 -= 0.05 * dW1
        m.b1 -= 0.05 * db1
        m.W2 -= 0.05 * dW2
        m.b2 -= 0.05 * db2

    # Phase 2: fine-tune on retain set to recover general accuracy
    if len(retain_X) > 0:
        m.train(retain_X, retain_y, epochs=100, lr=0.05)

    return m


def weight_delta_norm(model_before, model_after) -> float:
    """
    Compute the L-inf norm of the weight change: max(|W - W'|).
    A sane unlearning run should change weights, but not catastrophically —
    a very large delta suggests the GAU diverged and should be rejected.
    """
    deltas = []
    for attr in ("W1", "b1", "W2", "b2"):
        w_before = getattr(model_before, attr)
        w_after  = getattr(model_after, attr)
        deltas.append(float(np.abs(w_before - w_after).max()))
    return max(deltas)


def _sigmoid(x):
    return 1 / (1 + np.exp(-np.clip(x, -30, 30)))
