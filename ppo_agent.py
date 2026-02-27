"""
rl/ppo_agent.py
===============
Proximal Policy Optimization (PPO) agent for CyberWar.

Pure numpy — no PyTorch/TensorFlow dependency.

Architecture
------------
  Observation → featurize() → flat float vector
      → Policy MLP  → logits over action grid → masked softmax → action
      → Value  MLP  → scalar V(s)

Action grid
-----------
  Each "action" is a (action_type_index, node_index) pair flattened into a
  single integer.  Illegal actions (e.g. exploit on an isolated node, restore
  on a healthy node) are masked to -inf before softmax so the policy never
  wastes probability mass on impossible moves.

Training
--------
  Self-play: RLRedAgent trains against a frozen HeuristicBlueAgent,
             RLBlueAgent trains against a frozen HeuristicRedAgent.

  The Trainer runs N episodes, collects (s, a, logp, r, done, V) rollouts,
  computes GAE advantages, then runs K epochs of minibatch PPO updates.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np

from env.network import Team
from env.actions import Action, ActionType
from env.observation import Observation, NodeObservation
from agents.agents import BaseAgent


# ──────────────────────────────────────────────────────────────────────────────
# Action catalogue (keep in sync with main action space)
# ──────────────────────────────────────────────────────────────────────────────

RED_ACTION_TYPES: List[ActionType] = [
    ActionType.SCAN, ActionType.EXPLOIT, ActionType.LATERAL_MOVE,
    ActionType.PRIVILEGE_ESC, ActionType.EXFILTRATE, ActionType.PERSIST,
    ActionType.DDOS, ActionType.PASS,
]

BLUE_ACTION_TYPES: List[ActionType] = [
    ActionType.MONITOR, ActionType.PATCH, ActionType.ISOLATE,
    ActionType.RESTORE, ActionType.DEPLOY_HONEYPOT, ActionType.HARDEN,
    ActionType.HUNT, ActionType.BLOCK_EDGE, ActionType.PASS,
]

# Features extracted per node (must match featurize_node())
NODE_FEATURES = 10
# Global features appended at end
GLOBAL_FEATURES = 4


# ──────────────────────────────────────────────────────────────────────────────
# Feature engineering
# ──────────────────────────────────────────────────────────────────────────────

# Canonical node ordering — fixed across all scenarios so vectors align.
# Extended to cover all three scenarios; missing nodes default to zeros.
ALL_KNOWN_NODES = [
    # Corporate
    "internet", "dmz_web", "dmz_mail", "fw_internal",
    "workstation1", "workstation2", "db_server", "file_server", "ad_server",
    # ICS
    "corp_laptop", "it_server", "historian", "hmi", "dmz_firewall",
    "plc_pump", "plc_valve",
    # Cloud
    "public_api", "lambda_fn", "ec2_app", "rds_db",
    "s3_bucket", "iam_role", "vpc_endpoint",
]
MAX_NODES = len(ALL_KNOWN_NODES)
STATE_DIM = MAX_NODES * NODE_FEATURES + GLOBAL_FEATURES


def featurize_node(n: Optional[NodeObservation], visible: bool) -> np.ndarray:
    """10-float feature vector for one node."""
    if n is None or not visible:
        return np.zeros(NODE_FEATURES, dtype=np.float32)

    type_enc = {"router": 0, "server": 1, "workstation": 2,
                "firewall": 3, "database": 4, "dmz": 5}
    owner_enc = {"red": 1.0, "blue": -1.0, "neutral": 0.0}

    return np.array([
        float(type_enc.get(n.node_type, 0)) / 5.0,  # node type
        owner_enc.get(n.owner, 0.0),                 # owner
        float(n.compromised),                        # is compromised
        float(n.isolated),                           # is isolated
        float(n.honeypot or False),                  # is honeypot
        float(n.alert_level or 0) / 100.0,           # alert level (normalised)
        float(n.data_exfil or 0.0),                  # exfil progress
        min(float(len(n.known_vulns)), 5.0) / 5.0,   # known vuln count
        float(n.alert_level or 0) / 100.0 * float(n.compromised),  # hot: compromised+alert
        1.0,                                         # visibility flag
    ], dtype=np.float32)


def featurize(obs: Observation, max_turns: int = 20) -> np.ndarray:
    """Convert an Observation into a fixed-length float32 vector."""
    vec = np.zeros(STATE_DIM, dtype=np.float32)

    for i, nid in enumerate(ALL_KNOWN_NODES):
        n = obs.visible_nodes.get(nid)
        vec[i * NODE_FEATURES:(i + 1) * NODE_FEATURES] = featurize_node(
            n, visible=(n is not None)
        )

    # Global features
    base = MAX_NODES * NODE_FEATURES
    vec[base + 0] = obs.turn / max_turns
    vec[base + 1] = obs.red_score  / 50.0
    vec[base + 2] = obs.blue_score / 50.0
    vec[base + 3] = float(len(obs.alerts)) / 5.0

    return vec


# ──────────────────────────────────────────────────────────────────────────────
# Action masking
# ──────────────────────────────────────────────────────────────────────────────

def legal_action_mask(
    obs: Observation,
    action_types: List[ActionType],
    node_order: List[str],
) -> np.ndarray:
    """
    Return a boolean mask of shape (n_action_types * n_nodes,).
    True = legal action, False = illegal (will be masked to -inf).
    """
    n_at = len(action_types)
    n_nd = len(node_order)
    mask = np.zeros(n_at * n_nd, dtype=bool)

    nodes = obs.visible_nodes
    compromised = {nid for nid, n in nodes.items() if n.compromised}
    isolated    = {nid for nid, n in nodes.items() if n.isolated}
    exploitable = {nid for nid, n in nodes.items()
                   if n.known_vulns and not n.compromised and not n.isolated}

    for ai, at in enumerate(action_types):
        for ni, nid in enumerate(node_order):
            flat = ai * n_nd + ni
            n = nodes.get(nid)

            if at == ActionType.PASS:
                mask[flat] = True
                continue

            if n is None:
                continue  # node not visible → illegal

            if at == ActionType.SCAN:
                mask[flat] = not n.compromised

            elif at == ActionType.EXPLOIT:
                mask[flat] = bool(n.known_vulns) and not n.compromised and not n.isolated

            elif at == ActionType.LATERAL_MOVE:
                # Legal if node is reachable from a compromised neighbor
                if nid not in compromised and not n.isolated:
                    for src, dst in obs.known_edges:
                        if dst == nid and src in compromised:
                            mask[flat] = True
                            break

            elif at == ActionType.PRIVILEGE_ESC:
                mask[flat] = n.compromised

            elif at == ActionType.EXFILTRATE:
                mask[flat] = n.compromised and (n.data_exfil or 0) < 1.0

            elif at == ActionType.PERSIST:
                mask[flat] = n.compromised

            elif at == ActionType.DDOS:
                mask[flat] = not n.compromised

            elif at == ActionType.MONITOR:
                mask[flat] = True

            elif at == ActionType.PATCH:
                mask[flat] = bool(n.known_vulns) and not n.isolated

            elif at == ActionType.ISOLATE:
                mask[flat] = not n.isolated

            elif at == ActionType.RESTORE:
                mask[flat] = n.compromised or n.isolated

            elif at == ActionType.DEPLOY_HONEYPOT:
                mask[flat] = not (n.honeypot or False)

            elif at == ActionType.HARDEN:
                mask[flat] = True

            elif at == ActionType.HUNT:
                mask[flat] = True

            elif at == ActionType.BLOCK_EDGE:
                mask[flat] = True

    # Always allow PASS (index for pass type on node 0)
    pass_idx = action_types.index(ActionType.PASS) if ActionType.PASS in action_types else None
    if pass_idx is not None:
        mask[pass_idx * n_nd] = True

    return mask


def decode_action(
    flat_idx: int,
    action_types: List[ActionType],
    node_order: List[str],
    agent_id: str,
    obs: Observation,
) -> Action:
    """Convert flat action index back to an Action object."""
    n_nd = len(node_order)
    ai   = flat_idx // n_nd
    ni   = flat_idx %  n_nd

    at  = action_types[ai]
    nid = node_order[ni]

    if at == ActionType.PASS:
        return Action(ActionType.PASS, agent_id)

    params = {}
    if at == ActionType.EXPLOIT:
        n = obs.visible_nodes.get(nid)
        if n and n.known_vulns:
            params["cve_id"] = n.known_vulns[0]

    if at == ActionType.LATERAL_MOVE:
        # Find a valid from_node
        for src, dst in obs.known_edges:
            if dst == nid and obs.visible_nodes.get(src, None) and \
               obs.visible_nodes[src].compromised:
                params["from_node"] = src
                break

    return Action(at, agent_id, target_node=nid, params=params)


# ──────────────────────────────────────────────────────────────────────────────
# MLP (pure numpy)
# ──────────────────────────────────────────────────────────────────────────────

def relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0, x)


def softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max())
    return e / e.sum()


class MLP:
    """Simple 2-hidden-layer MLP with He-initialised weights."""

    def __init__(self, in_dim: int, hidden: int, out_dim: int, rng: np.random.Generator):
        def he(fan_in, fan_out):
            return rng.standard_normal((fan_in, fan_out)).astype(np.float32) \
                   * math.sqrt(2.0 / fan_in)

        self.W1 = he(in_dim, hidden);  self.b1 = np.zeros(hidden,   dtype=np.float32)
        self.W2 = he(hidden, hidden);  self.b2 = np.zeros(hidden,   dtype=np.float32)
        self.W3 = he(hidden, out_dim); self.b3 = np.zeros(out_dim,  dtype=np.float32)

        # Adam moment buffers
        self._params = [self.W1, self.b1, self.W2, self.b2, self.W3, self.b3]
        self._m  = [np.zeros_like(p) for p in self._params]
        self._v  = [np.zeros_like(p) for p in self._params]
        self._t  = 0

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, list]:
        h1 = relu(x @ self.W1 + self.b1)
        h2 = relu(h1 @ self.W2 + self.b2)
        out = h2 @ self.W3 + self.b3
        cache = (x, h1, h2)
        return out, cache

    def backward(self, d_out: np.ndarray, cache: list) -> list:
        x, h1, h2 = cache
        dW3 = h2[:, None] * d_out[None, :]
        db3 = d_out
        dh2 = d_out @ self.W3.T
        dh2 *= (h2 > 0)
        dW2 = h1[:, None] * dh2[None, :]
        db2 = dh2
        dh1 = dh2 @ self.W2.T
        dh1 *= (h1 > 0)
        dW1 = x[:, None] * dh1[None, :]
        db1 = dh1
        return [dW1, db1, dW2, db2, dW3, db3]

    def adam_update(self, grads: list, lr: float = 3e-4,
                    beta1: float = 0.9, beta2: float = 0.999, eps: float = 1e-8):
        self._t += 1
        for i, (p, g, m, v) in enumerate(zip(self._params, grads, self._m, self._v)):
            m[:] = beta1 * m + (1 - beta1) * g
            v[:] = beta2 * v + (1 - beta2) * g * g
            m_hat = m / (1 - beta1 ** self._t)
            v_hat = v / (1 - beta2 ** self._t)
            p -= lr * m_hat / (np.sqrt(v_hat) + eps)

    def params_flat(self) -> np.ndarray:
        return np.concatenate([p.ravel() for p in self._params])

    def load_flat(self, flat: np.ndarray):
        idx = 0
        for p in self._params:
            n = p.size
            p[:] = flat[idx:idx + n].reshape(p.shape)
            idx += n

    def copy(self) -> "MLP":
        other = MLP.__new__(MLP)
        other.W1 = self.W1.copy(); other.b1 = self.b1.copy()
        other.W2 = self.W2.copy(); other.b2 = self.b2.copy()
        other.W3 = self.W3.copy(); other.b3 = self.b3.copy()
        other._params = [other.W1, other.b1, other.W2, other.b2, other.W3, other.b3]
        other._m  = [np.zeros_like(p) for p in other._params]
        other._v  = [np.zeros_like(p) for p in other._params]
        other._t  = self._t
        return other


# ──────────────────────────────────────────────────────────────────────────────
# PPO Policy
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PPOConfig:
    hidden_dim:    int   = 128
    lr:            float = 3e-4
    gamma:         float = 0.99    # discount
    lam:           float = 0.95    # GAE lambda
    clip_eps:      float = 0.2     # PPO clip
    value_coef:    float = 0.5
    entropy_coef:  float = 0.01
    n_epochs:      int   = 4       # PPO update epochs per batch
    batch_size:    int   = 64
    max_grad_norm: float = 0.5


class PPOPolicy:
    """
    Actor-critic with shared trunk.
    Actor  → logits over flat action space
    Critic → scalar V(s)
    """

    def __init__(self, state_dim: int, action_dim: int,
                 cfg: PPOConfig, seed: int = 42):
        self.cfg        = cfg
        self.action_dim = action_dim
        rng = np.random.default_rng(seed)
        self.actor  = MLP(state_dim, cfg.hidden_dim, action_dim, rng)
        self.critic = MLP(state_dim, cfg.hidden_dim, 1,          rng)

    def act(self, state: np.ndarray, mask: np.ndarray) -> Tuple[int, float, float]:
        """
        Sample an action.
        Returns (action_idx, log_prob, value).
        """
        logits, _ = self.actor.forward(state)
        logits = logits.copy()
        logits[~mask] = -1e9
        probs  = softmax(logits)
        probs  = np.clip(probs, 1e-9, 1.0)
        probs /= probs.sum()

        action = int(np.random.choice(len(probs), p=probs))
        logp   = float(np.log(probs[action]))

        value, _ = self.critic.forward(state)
        return action, logp, float(value[0])

    def evaluate(self, states: np.ndarray, actions: np.ndarray,
                 masks: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Batch evaluate: returns log_probs, values, entropies."""
        n = len(states)
        log_probs = np.zeros(n, dtype=np.float32)
        values    = np.zeros(n, dtype=np.float32)
        entropies = np.zeros(n, dtype=np.float32)

        for i in range(n):
            logits, _ = self.actor.forward(states[i])
            logits = logits.copy()
            logits[~masks[i]] = -1e9
            probs  = softmax(logits)
            probs  = np.clip(probs, 1e-9, 1.0)
            probs /= probs.sum()

            log_probs[i] = np.log(probs[actions[i]])
            entropies[i] = -np.sum(probs * np.log(probs))

            v, _ = self.critic.forward(states[i])
            values[i] = v[0]

        return log_probs, values, entropies

    def update(self, rollout: "Rollout") -> dict:
        """Run PPO update on a collected rollout. Returns loss metrics."""
        states, actions, old_logps, advantages, returns, masks = rollout.to_arrays()
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        metrics = {"policy_loss": [], "value_loss": [], "entropy": [], "kl": []}

        n = len(states)
        for _ in range(self.cfg.n_epochs):
            idx = np.random.permutation(n)
            for start in range(0, n, self.cfg.batch_size):
                b = idx[start:start + self.cfg.batch_size]
                bs, ba, bo, badv, bret, bm = (
                    states[b], actions[b], old_logps[b],
                    advantages[b], returns[b], masks[b]
                )
                B = len(bs)

                # ── Analytic actor gradients via manual backprop ──────────────
                # Forward pass: collect probs, logps, caches for each sample
                all_probs  = []
                all_caches = []
                new_logps  = np.zeros(B, dtype=np.float32)
                entropies  = np.zeros(B, dtype=np.float32)

                for i in range(B):
                    logits, cache = self.actor.forward(bs[i])
                    logits = logits.copy()
                    logits[~bm[i]] = -1e9
                    probs  = softmax(logits)
                    probs  = np.clip(probs, 1e-9, 1.0); probs /= probs.sum()
                    new_logps[i] = np.log(probs[ba[i]])
                    entropies[i] = -np.sum(probs * np.log(probs))
                    all_probs.append(probs)
                    all_caches.append(cache)

                ratio = np.exp(new_logps - bo)
                clipped = np.clip(ratio, 1 - self.cfg.clip_eps, 1 + self.cfg.clip_eps)
                use_clipped = np.abs(ratio - 1.0) > self.cfg.clip_eps

                # PPO policy loss gradient w.r.t. log_prob[i]
                # d(loss)/d(logp_i) = -(adv_i * ratio_i) if not clipped, else 0
                # plus entropy regularisation: d(-H)/d(logp_i) ≈ -(1 + logp_i)
                d_logp = np.where(
                    use_clipped,
                    0.0,
                    -badv * ratio,          # -adv * ratio = d(-surr1)/d(logp)
                ) / B
                d_logp += self.cfg.entropy_coef * (new_logps + 1.0) / B  # -dH/dlogp

                # Backprop d_logp → d_logits via softmax Jacobian
                # d_logp[i] → d_logit[j] = probs[j] * (delta(i==j) - probs[i]) * d_logp_wrt_probs
                # For action a: d(logp_a)/d(logit_j) = delta(a,j) - probs[j]
                actor_param_grads = [np.zeros_like(p) for p in self.actor._params]
                for i in range(B):
                    probs   = all_probs[i]
                    a       = ba[i]
                    d_lp_dl = -probs.copy()   # d(log p_a)/d(logit_j) = -p_j for j≠a
                    d_lp_dl[a] += 1.0         # +1 for j==a
                    d_logits = d_logp[i] * d_lp_dl   # shape (action_dim,)
                    grads_i  = self.actor.backward(d_logits, all_caches[i])
                    for k in range(len(actor_param_grads)):
                        actor_param_grads[k] += grads_i[k]

                # Gradient clipping
                flat_g = np.concatenate([g.ravel() for g in actor_param_grads])
                gnorm  = np.linalg.norm(flat_g)
                if gnorm > self.cfg.max_grad_norm:
                    scale = self.cfg.max_grad_norm / gnorm
                    actor_param_grads = [g * scale for g in actor_param_grads]

                self.actor.adam_update(actor_param_grads, self.cfg.lr)

                # ── Critic update (analytic MSE backprop) ────────────────────
                for i in range(B):
                    v_out, v_cache = self.critic.forward(bs[i])
                    err   = float(v_out[0]) - bret[i]
                    d_out = np.array([2.0 * err / B], dtype=np.float32)
                    grads = self.critic.backward(d_out, v_cache)
                    self.critic.adam_update(grads, self.cfg.lr)

                # ── Metrics ──────────────────────────────────────────────────
                policy_loss = -float(np.mean(np.minimum(ratio * badv, clipped * badv)))
                value_loss  = float(np.mean((np.array([
                    self.critic.forward(bs[i])[0][0] for i in range(B)
                ]) - bret) ** 2))
                kl = float(np.mean(bo - new_logps))

                metrics["policy_loss"].append(policy_loss)
                metrics["value_loss"].append(value_loss)
                metrics["entropy"].append(float(np.mean(entropies)))
                metrics["kl"].append(kl)

        return {k: float(np.mean(v)) for k, v in metrics.items()}

    def _unflatten_actor(self, flat: np.ndarray) -> list:
        grads = []
        idx = 0
        for p in self.actor._params:
            n = p.size
            grads.append(flat[idx:idx + n].reshape(p.shape))
            idx += n
        return grads

    def save(self, path: str):
        np.savez(path,
                 actor_flat  = self.actor.params_flat(),
                 critic_flat = self.critic.params_flat(),
                 actor_t     = np.array([self.actor._t]),
                 critic_t    = np.array([self.critic._t]))

    def load(self, path: str):
        if not path.endswith(".npz"):
            path += ".npz"
        d = np.load(path)
        self.actor.load_flat(d["actor_flat"])
        self.critic.load_flat(d["critic_flat"])
        self.actor._t  = int(d["actor_t"][0])
        self.critic._t = int(d["critic_t"][0])


# ──────────────────────────────────────────────────────────────────────────────
# Rollout buffer
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Rollout:
    states:     List[np.ndarray] = field(default_factory=list)
    actions:    List[int]        = field(default_factory=list)
    log_probs:  List[float]      = field(default_factory=list)
    rewards:    List[float]      = field(default_factory=list)
    values:     List[float]      = field(default_factory=list)
    dones:      List[bool]       = field(default_factory=list)
    masks:      List[np.ndarray] = field(default_factory=list)

    def add(self, s, a, lp, r, v, done, mask):
        self.states.append(s)
        self.actions.append(a)
        self.log_probs.append(lp)
        self.rewards.append(r)
        self.values.append(v)
        self.dones.append(done)
        self.masks.append(mask)

    def compute_gae(self, last_value: float, gamma: float, lam: float):
        """Generalised Advantage Estimation."""
        T         = len(self.rewards)
        adv       = np.zeros(T, dtype=np.float32)
        last_gae  = 0.0
        for t in reversed(range(T)):
            next_val = last_value if t == T - 1 else self.values[t + 1]
            delta    = self.rewards[t] + gamma * next_val * (1 - self.dones[t]) - self.values[t]
            adv[t]   = last_gae = delta + gamma * lam * (1 - self.dones[t]) * last_gae
        returns = adv + np.array(self.values, dtype=np.float32)
        return adv, returns

    def to_arrays(self, gamma: float = 0.99, lam: float = 0.95):
        adv, ret = self.compute_gae(0.0, gamma, lam)
        return (
            np.array(self.states,    dtype=np.float32),
            np.array(self.actions,   dtype=np.int32),
            np.array(self.log_probs, dtype=np.float32),
            adv, ret,
            np.array(self.masks,     dtype=bool),
        )

    def __len__(self):
        return len(self.rewards)


# ──────────────────────────────────────────────────────────────────────────────
# RL Agent wrappers (plug into BaseAgent interface)
# ──────────────────────────────────────────────────────────────────────────────

class RLRedAgent(BaseAgent):
    """PPO-trained red-team agent."""

    def __init__(self, start_node: str, policy: PPOPolicy,
                 node_order: List[str], training: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.start_node = start_node
        self.policy     = policy
        self.node_order = node_order
        self.training   = training
        self._last_state: Optional[np.ndarray] = None
        self._last_action: Optional[int]       = None
        self._last_logp:   Optional[float]     = None
        self._last_value:  Optional[float]     = None
        self._last_mask:   Optional[np.ndarray]= None
        self.rollout:      Rollout             = Rollout()
        self.episode_reward: float             = 0.0

    def act(self, obs: Observation) -> Action:
        state = featurize(obs)
        mask  = legal_action_mask(obs, RED_ACTION_TYPES, self.node_order)

        if not mask.any():
            mask[RED_ACTION_TYPES.index(ActionType.PASS) * len(self.node_order)] = True

        action_idx, logp, value = self.policy.act(state, mask)

        self._last_state  = state
        self._last_action = action_idx
        self._last_logp   = logp
        self._last_value  = value
        self._last_mask   = mask

        return decode_action(action_idx, RED_ACTION_TYPES, self.node_order,
                             self.agent_id, obs)

    def record_step(self, reward: float, done: bool):
        if self.training and self._last_state is not None:
            self.rollout.add(
                self._last_state, self._last_action, self._last_logp,
                reward, self._last_value, done, self._last_mask
            )
            self.episode_reward += reward

    def reset_episode(self):
        self.episode_reward = 0.0

    def update(self) -> dict:
        if not self.training or len(self.rollout) == 0:
            return {}
        cfg = self.policy.cfg
        metrics = self.policy.update(self.rollout)
        self.rollout = Rollout()
        return metrics


class RLBlueAgent(BaseAgent):
    """PPO-trained blue-team agent."""

    def __init__(self, policy: PPOPolicy, node_order: List[str],
                 training: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.policy     = policy
        self.node_order = node_order
        self.training   = training
        self._last_state: Optional[np.ndarray] = None
        self._last_action: Optional[int]       = None
        self._last_logp:   Optional[float]     = None
        self._last_value:  Optional[float]     = None
        self._last_mask:   Optional[np.ndarray]= None
        self.rollout:      Rollout             = Rollout()
        self.episode_reward: float             = 0.0

    def act(self, obs: Observation) -> Action:
        state = featurize(obs)
        mask  = legal_action_mask(obs, BLUE_ACTION_TYPES, self.node_order)

        if not mask.any():
            mask[BLUE_ACTION_TYPES.index(ActionType.PASS) * len(self.node_order)] = True

        action_idx, logp, value = self.policy.act(state, mask)

        self._last_state  = state
        self._last_action = action_idx
        self._last_logp   = logp
        self._last_value  = value
        self._last_mask   = mask

        return decode_action(action_idx, BLUE_ACTION_TYPES, self.node_order,
                             self.agent_id, obs)

    def record_step(self, reward: float, done: bool):
        if self.training and self._last_state is not None:
            self.rollout.add(
                self._last_state, self._last_action, self._last_logp,
                reward, self._last_value, done, self._last_mask
            )
            self.episode_reward += reward

    def reset_episode(self):
        self.episode_reward = 0.0

    def update(self) -> dict:
        if not self.training or len(self.rollout) == 0:
            return {}
        metrics = self.policy.update(self.rollout)
        self.rollout = Rollout()
        return metrics
