"""
Action System
-------------
Defines the action space for Red and Blue agents.
Each Action is a dataclass that captures intent.
The Engine resolves actions against the Network and returns Outcomes.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Any
import random


# ---------------------------------------------------------------------------
# Action Types
# ---------------------------------------------------------------------------

class ActionType(Enum):
    # --- RED (attacker) ---
    SCAN            = "scan"             # discover nodes/services
    EXPLOIT         = "exploit"          # exploit a vulnerability
    LATERAL_MOVE    = "lateral_move"     # pivot to adjacent node
    PRIVILEGE_ESC   = "privilege_esc"    # gain root/admin
    EXFILTRATE      = "exfiltrate"       # steal data
    PERSIST         = "persist"          # install backdoor/persistence
    DDOS            = "ddos"             # degrade service availability
    SPOOF           = "spoof"            # impersonate legitimate traffic

    # --- BLUE (defender) ---
    MONITOR         = "monitor"          # watch a node/edge for anomalies
    PATCH           = "patch"            # fix a vulnerability
    ISOLATE         = "isolate"          # quarantine a node
    RESTORE         = "restore"          # restore a node from backup
    DEPLOY_HONEYPOT = "deploy_honeypot"  # trap red agents
    DEPLOY_DECOY    = "deploy_decoy"     # fake high-value target
    HARDEN          = "harden"           # increase patch level / close ports
    HUNT            = "hunt"             # active threat hunt on a node
    BLOCK_EDGE      = "block_edge"       # firewall rule on an edge

    # --- SHARED ---
    PASS            = "pass"             # do nothing this turn


# ---------------------------------------------------------------------------
# Base Action
# ---------------------------------------------------------------------------

@dataclass
class Action:
    action_type: ActionType
    actor_id:    str                     # agent that issued this
    target_node: Optional[str] = None   # primary target node
    target_edge: Optional[tuple] = None # (src, dst) for edge actions
    params:      dict = field(default_factory=dict)

    def __repr__(self):
        t = self.target_node or self.target_edge or "—"
        return f"Action({self.actor_id}::{self.action_type.value}→{t})"


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------

class OutcomeStatus(Enum):
    SUCCESS    = "success"
    FAILURE    = "failure"
    PARTIAL    = "partial"
    DETECTED   = "detected"   # action succeeded but blue noticed


@dataclass
class Outcome:
    action:        Action
    status:        OutcomeStatus
    message:       str                   = ""
    effects:       dict[str, Any]        = field(default_factory=dict)
    alerts:        list[str]             = field(default_factory=list)
    reward:        float                 = 0.0

    def __repr__(self):
        return f"Outcome({self.status.value}: {self.message[:60]})"


# ---------------------------------------------------------------------------
# Action Resolver — pure functions, called by the Engine
# ---------------------------------------------------------------------------

class ActionResolver:
    """
    Resolves an Action against the live Network state.
    Returns an Outcome with side-effects described (Engine applies them).
    """

    def __init__(self, rng: random.Random = None):
        self.rng = rng or random.Random()

    def resolve(self, action: Action, network) -> Outcome:
        dispatch = {
            ActionType.SCAN:            self._scan,
            ActionType.EXPLOIT:         self._exploit,
            ActionType.LATERAL_MOVE:    self._lateral_move,
            ActionType.PRIVILEGE_ESC:   self._privilege_esc,
            ActionType.EXFILTRATE:      self._exfiltrate,
            ActionType.PERSIST:         self._persist,
            ActionType.DDOS:            self._ddos,
            ActionType.MONITOR:         self._monitor,
            ActionType.PATCH:           self._patch,
            ActionType.ISOLATE:         self._isolate,
            ActionType.RESTORE:         self._restore,
            ActionType.DEPLOY_HONEYPOT: self._deploy_honeypot,
            ActionType.DEPLOY_DECOY:    self._deploy_decoy,
            ActionType.HARDEN:          self._harden,
            ActionType.HUNT:            self._hunt,
            ActionType.BLOCK_EDGE:      self._block_edge,
            ActionType.PASS:            self._pass,
        }
        fn = dispatch.get(action.action_type, self._unknown)
        return fn(action, network)

    # ------------------------------------------------------------------
    # RED actions
    # ------------------------------------------------------------------

    def _scan(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        if not node.is_accessible():
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"Node {node.id} is isolated — unreachable.",
                           reward=-0.1)
        # Honeypot check
        if node.state.honeypot:
            return Outcome(action, OutcomeStatus.DETECTED,
                           f"Scanned honeypot {node.id}! Blue alerted.",
                           effects={"alert_node": node.id, "alert_delta": 40},
                           alerts=[f"HONEYPOT triggered by scan on {node.id}"],
                           reward=-0.5)
        discovered = {
            "node_id":   node.id,
            "node_type": node.node_type.value,
            "services":  [str(s) for s in node.services if s.running],
            "vulns":     [v.cve_id for v in node.exploitable_vulns()],
        }
        alert_delta = 5 if network.edge(*action.params.get("via", (node.id, node.id))) and \
                          network.edge(*action.params.get("via", (node.id, node.id))).monitored \
                      else 2
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Scanned {node.id}: found {len(discovered['vulns'])} vulns.",
                       effects={"discovered": discovered, "alert_delta": alert_delta},
                       reward=0.2)

    def _exploit(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        cve  = action.params.get("cve_id")
        vuln = node.has_vuln(cve) if cve else (node.exploitable_vulns() or [None])[0]

        if not vuln:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"No exploitable vulnerability on {node.id}.",
                           reward=-0.1)
        if node.state.isolated:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"{node.id} is isolated.", reward=-0.2)
        if node.state.honeypot:
            return Outcome(action, OutcomeStatus.DETECTED,
                           f"Exploit on honeypot {node.id}! Massive alert.",
                           effects={"alert_delta": 80},
                           alerts=[f"HONEYPOT exploit triggered on {node.id}"],
                           reward=-1.0)

        # Probability scales with CVSS and patch level
        patch_penalty = node.state.patch_level * 0.1
        p_success = min(0.95, max(0.1, (vuln.cvss / 10.0) - patch_penalty))
        roll = self.rng.random()

        if roll < p_success:
            alert_delta = 20 if not node.state.compromised else 5
            return Outcome(action, OutcomeStatus.SUCCESS,
                           f"Exploited {vuln.cve_id} on {node.id} (roll={roll:.2f}).",
                           effects={"compromise_node": node.id, "mark_exploited": vuln.cve_id,
                                    "alert_delta": alert_delta},
                           reward=node.value * 1.0)
        else:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"Exploit failed on {node.id} (roll={roll:.2f}, need<{p_success:.2f}).",
                           effects={"alert_delta": 10},
                           reward=-0.2)

    def _lateral_move(self, action: Action, network) -> Outcome:
        src  = action.params.get("from_node")
        dst  = action.target_node
        src_node = network.node(src)
        dst_node = network.node(dst)
        edge = network.edge(src, dst)

        if not src_node.state.compromised:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"Cannot move from uncompromised node {src}.", reward=-0.3)
        if dst_node.state.isolated:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"{dst} is isolated.", reward=-0.1)
        if edge is None:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"No path from {src} to {dst}.", reward=-0.2)

        alert_delta = 30 if edge.monitored else 8
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Laterally moved from {src} to {dst}.",
                       effects={"compromise_node": dst, "alert_delta": alert_delta,
                                "alert_edge": (src, dst)},
                       alerts=[f"Suspicious lateral traffic {src}→{dst}"] if edge.monitored else [],
                       reward=dst_node.value * 0.8)

    def _privilege_esc(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        if not node.state.compromised:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"Must compromise {node.id} first.", reward=-0.2)
        p = 0.7 - (node.state.patch_level * 0.15)
        if self.rng.random() < max(0.1, p):
            return Outcome(action, OutcomeStatus.SUCCESS,
                           f"Gained elevated privileges on {node.id}.",
                           effects={"priv_esc": node.id, "alert_delta": 15},
                           reward=1.5)
        return Outcome(action, OutcomeStatus.FAILURE,
                       f"Privilege escalation failed on {node.id}.",
                       effects={"alert_delta": 10}, reward=-0.1)

    def _exfiltrate(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        if not node.state.compromised:
            return Outcome(action, OutcomeStatus.FAILURE,
                           f"Cannot exfiltrate from {node.id}: not owned.", reward=-0.2)
        amount = action.params.get("amount", 0.25)  # fraction per turn
        new_exfil = min(1.0, node.state.data_exfil + amount)
        delta = new_exfil - node.state.data_exfil
        alert_delta = int(40 * delta)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Exfiltrated {delta*100:.0f}% data from {node.id}.",
                       effects={"exfil_delta": (node.id, delta), "alert_delta": alert_delta},
                       reward=node.value * delta * 2.0)

    def _persist(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        if not node.state.compromised:
            return Outcome(action, OutcomeStatus.FAILURE, f"{node.id} not compromised.", reward=-0.1)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Persistence installed on {node.id}.",
                       effects={"persist": node.id, "alert_delta": 5},
                       reward=0.5)

    def _ddos(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"DDoS launched against {node.id} — services degraded.",
                       effects={"ddos": node.id, "alert_delta": 25},
                       alerts=[f"Traffic spike detected on {node.id}"],
                       reward=0.3)

    # ------------------------------------------------------------------
    # BLUE actions
    # ------------------------------------------------------------------

    def _monitor(self, action: Action, network) -> Outcome:
        target = action.target_node or str(action.target_edge)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Monitoring active on {target}.",
                       effects={"monitor": {"node": action.target_node, "edge": action.target_edge}},
                       reward=0.1)

    def _patch(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        cve  = action.params.get("cve_id")
        if cve:
            vuln = node.has_vuln(cve)
            if vuln:
                return Outcome(action, OutcomeStatus.SUCCESS,
                               f"Patched {cve} on {node.id}.",
                               effects={"patch_vuln": (node.id, cve)},
                               reward=0.5)
            return Outcome(action, OutcomeStatus.FAILURE, f"{cve} not found on {node.id}.")
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"General hardening patch applied to {node.id}.",
                       effects={"patch_level_up": node.id},
                       reward=0.3)

    def _isolate(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        if node.state.isolated:
            return Outcome(action, OutcomeStatus.FAILURE, f"{node.id} already isolated.")
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Node {node.id} isolated from network.",
                       effects={"isolate": node.id},
                       reward=1.0 if node.state.compromised else -0.2)

    def _restore(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Node {node.id} restored from clean backup.",
                       effects={"restore": node.id},
                       reward=node.value * 1.2 if node.state.compromised else 0.1)

    def _deploy_honeypot(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Honeypot deployed on {node.id}.",
                       effects={"honeypot": node.id},
                       reward=0.4)

    def _deploy_decoy(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Decoy deployed on {node.id}.",
                       effects={"decoy": node.id},
                       reward=0.3)

    def _harden(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Hardened {node.id} (patch_level +1).",
                       effects={"patch_level_up": node.id},
                       reward=0.4)

    def _hunt(self, action: Action, network) -> Outcome:
        node = network.node(action.target_node)
        found = node.state.compromised
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Threat hunt on {node.id}: {'COMPROMISE FOUND' if found else 'clean'}.",
                       effects={"hunt_result": (node.id, found), "alert_reset": node.id if found else None},
                       alerts=[f"Confirmed compromise on {node.id}!"] if found else [],
                       reward=2.0 if found else 0.05)

    def _block_edge(self, action: Action, network) -> Outcome:
        src, dst = action.target_edge
        return Outcome(action, OutcomeStatus.SUCCESS,
                       f"Firewall rule blocking {src}→{dst}.",
                       effects={"block_edge": (src, dst)},
                       reward=0.5)

    def _pass(self, action: Action, network) -> Outcome:
        return Outcome(action, OutcomeStatus.SUCCESS, "Agent passed this turn.", reward=0.0)

    def _unknown(self, action: Action, network) -> Outcome:
        return Outcome(action, OutcomeStatus.FAILURE, f"Unknown action: {action.action_type}")
