"""
Human Agent
-----------
A passthrough agent whose action is set externally by the web API
before engine.step() is called.

The GameSession in app.py:
  1. Calls session.set_human_action(action_dict) with what the player submitted
  2. Calls engine.step() — which calls agent.act(obs) for both agents
  3. HumanAgent.act() just returns the pre-loaded action

If no action has been set (e.g. a timeout or bug), falls back to PASS.
"""

from __future__ import annotations
from typing import Optional
import random

from env.network import Team
from env.actions import Action, ActionType
from env.observation import Observation
from agents.agents import BaseAgent


class HumanAgent(BaseAgent):
    """Works for either team — team is set at construction time."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._pending: Optional[Action] = None

    def load_action(self, action: Action):
        """Called by the API before engine.step()."""
        self._pending = action

    def act(self, obs: Observation) -> Action:
        if self._pending is not None:
            action = self._pending
            self._pending = None
            return action
        # Fallback — should not normally happen
        return Action(ActionType.PASS, self.agent_id)


class HumanRedAgent(HumanAgent):
    """Human playing as Red (attacker)."""
    def __init__(self, start_node: str, **kwargs):
        super().__init__(**kwargs)
        self.start_node = start_node


class HumanBlueAgent(HumanAgent):
    """Human playing as Blue (defender)."""
    pass


# ─── Helpers ─────────────────────────────────────────────────────────────────

# Red actions and which teams they belong to
RED_ACTION_TYPES = [
    ActionType.SCAN,
    ActionType.EXPLOIT,
    ActionType.LATERAL_MOVE,
    ActionType.PRIVILEGE_ESC,
    ActionType.EXFILTRATE,
    ActionType.PERSIST,
    ActionType.DDOS,
    ActionType.PASS,
]

BLUE_ACTION_TYPES = [
    ActionType.MONITOR,
    ActionType.PATCH,
    ActionType.ISOLATE,
    ActionType.RESTORE,
    ActionType.DEPLOY_HONEYPOT,
    ActionType.HARDEN,
    ActionType.HUNT,
    ActionType.PASS,
]

ACTION_DESCRIPTIONS = {
    "scan":           "Scan a node to discover its vulnerabilities and services",
    "exploit":        "Exploit a vulnerability to compromise a node",
    "lateral_move":   "Pivot from a compromised node into an adjacent one",
    "privilege_esc":  "Escalate privileges on a compromised node",
    "exfiltrate":     "Steal data from a compromised node",
    "persist":        "Install a backdoor on a compromised node",
    "ddos":           "Degrade availability of a target node",
    "monitor":        "Watch a node for anomalies — raises alert sensitivity",
    "patch":          "Fix a vulnerability on a node",
    "isolate":        "Quarantine a suspicious node from the network",
    "restore":        "Restore a compromised/isolated node from backup",
    "deploy_honeypot":"Deploy a honeypot trap on a node",
    "harden":         "Harden a node (increase its patch level)",
    "hunt":           "Actively threat-hunt a high-alert node",
    "pass":           "Do nothing this turn",
}


def compute_available_actions(obs: Observation) -> list[dict]:
    """
    Given an observation, return the list of available actions for the human,
    including valid targets for each action type.
    """
    team       = obs.team
    nodes      = obs.visible_nodes
    edges      = obs.known_edges
    compromised = [nid for nid, n in nodes.items() if n.compromised]
    exploitable = [(nid, n.known_vulns) for nid, n in nodes.items()
                   if n.known_vulns and not n.compromised and not n.isolated]
    isolated    = [nid for nid, n in nodes.items() if n.isolated]

    actions = []

    if team == Team.RED:
        # Scan — any visible node
        visible = list(nodes.keys())
        if visible:
            actions.append({
                "action_type": "scan",
                "label":       "Scan",
                "description": ACTION_DESCRIPTIONS["scan"],
                "targets":     [{"node": n, "label": n} for n in visible],
                "needs_target": True,
                "needs_cve":   False,
                "needs_from":  False,
            })

        # Exploit — nodes with known vulns
        if exploitable:
            for nid, vulns in exploitable:
                actions.append({
                    "action_type": "exploit",
                    "label":       f"Exploit → {nid}",
                    "description": ACTION_DESCRIPTIONS["exploit"],
                    "targets":     [{"node": nid, "label": nid}],
                    "cve_options": vulns,
                    "needs_target": True,
                    "needs_cve":   True,
                    "needs_from":  False,
                })

        # Lateral move — from compromised to reachable uncompromised
        lateral_opts = []
        for src, dst in edges:
            src_node = nodes.get(src)
            dst_node = nodes.get(dst)
            if (src_node and src_node.compromised and
                    dst_node and not dst_node.compromised and not dst_node.isolated):
                lateral_opts.append({"node": dst, "from": src, "label": f"{src} → {dst}"})
        if lateral_opts:
            actions.append({
                "action_type": "lateral_move",
                "label":       "Lateral Move",
                "description": ACTION_DESCRIPTIONS["lateral_move"],
                "targets":     lateral_opts,
                "needs_target": True,
                "needs_cve":   False,
                "needs_from":  True,
            })

        # Exfiltrate — compromised nodes with exfil < 100%
        exfil_targets = [nid for nid in compromised
                         if (nodes[nid].data_exfil or 0) < 1.0]
        if exfil_targets:
            actions.append({
                "action_type": "exfiltrate",
                "label":       "Exfiltrate",
                "description": ACTION_DESCRIPTIONS["exfiltrate"],
                "targets":     [{"node": n, "label": n} for n in exfil_targets],
                "needs_target": True,
                "needs_cve":   False,
                "needs_from":  False,
            })

        # Privilege escalation — compromised nodes
        if compromised:
            actions.append({
                "action_type": "privilege_esc",
                "label":       "Privilege Escalation",
                "description": ACTION_DESCRIPTIONS["privilege_esc"],
                "targets":     [{"node": n, "label": n} for n in compromised],
                "needs_target": True,
                "needs_cve":   False,
                "needs_from":  False,
            })

        # DDOS — any visible node
        if visible:
            actions.append({
                "action_type": "ddos",
                "label":       "DDoS",
                "description": ACTION_DESCRIPTIONS["ddos"],
                "targets":     [{"node": n, "label": n} for n in visible],
                "needs_target": True,
                "needs_cve":   False,
                "needs_from":  False,
            })

    else:  # BLUE
        visible = list(nodes.keys())

        # Monitor — any node
        if visible:
            actions.append({
                "action_type": "monitor",
                "label":       "Monitor",
                "description": ACTION_DESCRIPTIONS["monitor"],
                "targets":     [{"node": n, "label": n} for n in visible],
                "needs_target": True, "needs_cve": False, "needs_from": False,
            })

        # Patch — nodes with vulns
        patchable = [(nid, n.known_vulns) for nid, n in nodes.items()
                     if n.known_vulns and not n.isolated]
        for nid, vulns in patchable:
            actions.append({
                "action_type": "patch",
                "label":       f"Patch → {nid}",
                "description": ACTION_DESCRIPTIONS["patch"],
                "targets":     [{"node": nid, "label": nid}],
                "cve_options": vulns,
                "needs_target": True, "needs_cve": True, "needs_from": False,
            })

        # Isolate — compromised or high-alert
        isolatable = [nid for nid, n in nodes.items()
                      if (n.compromised or (n.alert_level or 0) > 20) and not n.isolated]
        if isolatable:
            actions.append({
                "action_type": "isolate",
                "label":       "Isolate",
                "description": ACTION_DESCRIPTIONS["isolate"],
                "targets":     [{"node": n, "label": n} for n in isolatable],
                "needs_target": True, "needs_cve": False, "needs_from": False,
            })

        # Restore — compromised or isolated
        restorable = compromised + [n for n in isolated if n not in compromised]
        if restorable:
            actions.append({
                "action_type": "restore",
                "label":       "Restore",
                "description": ACTION_DESCRIPTIONS["restore"],
                "targets":     [{"node": n, "label": n} for n in restorable],
                "needs_target": True, "needs_cve": False, "needs_from": False,
            })

        # Harden + Deploy Honeypot + Hunt — any visible node
        if visible:
            actions.append({
                "action_type": "harden",
                "label":       "Harden",
                "description": ACTION_DESCRIPTIONS["harden"],
                "targets":     [{"node": n, "label": n} for n in visible],
                "needs_target": True, "needs_cve": False, "needs_from": False,
            })
            actions.append({
                "action_type": "deploy_honeypot",
                "label":       "Deploy Honeypot",
                "description": ACTION_DESCRIPTIONS["deploy_honeypot"],
                "targets":     [{"node": n, "label": n} for n in visible],
                "needs_target": True, "needs_cve": False, "needs_from": False,
            })
            hunt_targets = [nid for nid, n in nodes.items() if (n.alert_level or 0) > 0]
            if not hunt_targets:
                hunt_targets = visible
            actions.append({
                "action_type": "hunt",
                "label":       "Threat Hunt",
                "description": ACTION_DESCRIPTIONS["hunt"],
                "targets":     [{"node": n, "label": n} for n in hunt_targets],
                "needs_target": True, "needs_cve": False, "needs_from": False,
            })

    # Pass — always available
    actions.append({
        "action_type": "pass",
        "label":       "Pass",
        "description": ACTION_DESCRIPTIONS["pass"],
        "targets":     [],
        "needs_target": False, "needs_cve": False, "needs_from": False,
    })

    return actions
