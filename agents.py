"""
Agents
------
BaseAgent:      Abstract interface all agents implement.
RandomRedAgent: Attacks randomly — useful as a baseline.
HeuristicRedAgent: Prioritizes high-value, low-patch targets.
RandomBlueAgent: Defends randomly.
HeuristicBlueAgent: Prioritizes high-alert nodes, hunts, isolates.
LLMAgent:       Hook for connecting an LLM (e.g. Claude) as an agent.
"""

from __future__ import annotations
import random
from abc import ABC, abstractmethod
from typing import Optional

from env.network import Team
from env.actions import Action, ActionType
from env.observation import Observation


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    def __init__(self, agent_id: str, team: Team, rng: random.Random = None):
        self.agent_id = agent_id
        self.team     = team
        self.rng      = rng or random.Random()
        self.memory:  dict = {}   # agent can store state between turns

    @abstractmethod
    def act(self, obs: Observation) -> Action:
        """Given an observation, return the next action."""
        ...

    def _pass(self) -> Action:
        return Action(ActionType.PASS, self.agent_id)


# ---------------------------------------------------------------------------
# RED Agents
# ---------------------------------------------------------------------------

class RandomRedAgent(BaseAgent):
    """Scans and exploits randomly. No memory."""

    def __init__(self, start_node: str, **kwargs):
        super().__init__(**kwargs)
        self.start_node  = start_node
        self.foothold:   Optional[str] = None

    def act(self, obs: Observation) -> Action:
        # First turn — we always start from our entry point
        if self.foothold is None:
            self.foothold = self.start_node
            return Action(ActionType.SCAN, self.agent_id, target_node=self.start_node)

        # Pick a random known node to act on
        known = list(obs.visible_nodes.keys())
        if not known:
            return self._pass()

        target = self.rng.choice(known)
        node   = obs.node(target)

        roll = self.rng.random()

        if roll < 0.3 and node.known_vulns and not node.compromised:
            return Action(ActionType.EXPLOIT, self.agent_id, target_node=target,
                          params={"cve_id": node.known_vulns[0]})
        elif roll < 0.6:
            return Action(ActionType.SCAN, self.agent_id, target_node=target)
        elif roll < 0.8 and node.compromised:
            return Action(ActionType.EXFILTRATE, self.agent_id, target_node=target)
        else:
            return self._pass()


class HeuristicRedAgent(BaseAgent):
    """
    Triage-driven attacker:
    1. Immediately exploit reachable vulns (don't waste turns scanning the entry node)
    2. Scan unseen reachable nodes
    3. Lateral move into new territory
    4. Exfiltrate from crown-jewel nodes
    """

    def __init__(self, start_node: str, **kwargs):
        super().__init__(**kwargs)
        self.start_node  = start_node
        self.foothold:   Optional[str] = None
        self.scanned:    set = set()
        self.turn:       int = 0

    def act(self, obs: Observation) -> Action:
        self.turn += 1

        # Bootstrap: mark start node as known
        if self.foothold is None:
            self.foothold = self.start_node
            self.scanned.add(self.start_node)

        compromised = obs.compromised_nodes()
        exploitable = obs.exploitable_nodes()

        # Priority 1: Exploit any visible node we haven't fully exploited yet.
        # We also blindly try common CVEs on visible unscanned nodes (no prior scan needed).
        all_visible = list(obs.visible_nodes.keys())
        # Try exploiting unscanned visible nodes using their discovered vulns
        for nid in all_visible:
            n = obs.node(nid)
            if n and n.known_vulns and not n.compromised and not n.isolated:
                return Action(ActionType.EXPLOIT, self.agent_id, target_node=nid,
                              params={"cve_id": n.known_vulns[0]})

        # Priority 2: Scan unseen visible nodes to discover their vulns
        unseen = [nid for nid in all_visible if nid not in self.scanned
                  and nid != self.start_node]
        if unseen:
            target = unseen[0]
            self.scanned.add(target)
            return Action(ActionType.SCAN, self.agent_id, target_node=target)

        # Priority 3: Lateral movement into reachable uncompromised nodes
        reachable_new = []
        for src, dst in obs.known_edges:
            if src in compromised:
                dst_node = obs.node(dst)
                if dst_node and not dst_node.compromised and not dst_node.isolated:
                    reachable_new.append((src, dst))

        if reachable_new:
            src, dst = self.rng.choice(reachable_new)
            return Action(ActionType.LATERAL_MOVE, self.agent_id, target_node=dst,
                          params={"from_node": src})

        # Priority 4: Exfiltrate from best compromised node
        if compromised:
            unfinished = [n for n in compromised
                          if (obs.node(n).data_exfil or 0.0) < 1.0]
            if unfinished:
                return Action(ActionType.EXFILTRATE, self.agent_id,
                              target_node=unfinished[0])

        # Priority 5: Privilege escalation
        if compromised and self.rng.random() < 0.3:
            target = self.rng.choice(compromised)
            return Action(ActionType.PRIVILEGE_ESC, self.agent_id, target_node=target)

        # Fallback
        if all_visible:
            return Action(ActionType.SCAN, self.agent_id,
                          target_node=self.rng.choice(all_visible))
        return self._pass()


# ---------------------------------------------------------------------------
# BLUE Agents
# ---------------------------------------------------------------------------

class RandomBlueAgent(BaseAgent):
    """Monitors and patches randomly."""

    def act(self, obs: Observation) -> Action:
        nodes = list(obs.visible_nodes.keys())
        if not nodes:
            return self._pass()
        target = self.rng.choice(nodes)
        roll   = self.rng.random()

        if roll < 0.3:
            return Action(ActionType.PATCH, self.agent_id, target_node=target)
        elif roll < 0.5:
            return Action(ActionType.MONITOR, self.agent_id, target_node=target)
        elif roll < 0.65:
            return Action(ActionType.HARDEN, self.agent_id, target_node=target)
        else:
            return self._pass()


class HeuristicBlueAgent(BaseAgent):
    """
    Triage-driven defense:
    1. If alerts → isolate/hunt high-alert nodes
    2. If compromised known → restore
    3. Otherwise → monitor + harden high-value nodes
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.monitored: set = set()
        self.turn: int = 0

    def act(self, obs: Observation) -> Action:
        self.turn += 1
        nodes = obs.visible_nodes

        # Identify compromised and high-alert nodes
        compromised = [nid for nid, n in nodes.items() if n.compromised]
        high_alert  = sorted(
            [(nid, n.alert_level) for nid, n in nodes.items() if n.alert_level],
            key=lambda x: -x[1]
        )

        # Priority 1: Restore confirmed compromised
        if compromised:
            target = compromised[0]
            if self.rng.random() < 0.6:
                return Action(ActionType.RESTORE, self.agent_id, target_node=target)
            else:
                return Action(ActionType.ISOLATE, self.agent_id, target_node=target)

        # Priority 2: Hunt on high-alert nodes
        if high_alert and high_alert[0][1] > 30:
            target = high_alert[0][0]
            return Action(ActionType.HUNT, self.agent_id, target_node=target)

        # Priority 3: Patch vulnerable nodes
        vulnerable = [nid for nid, n in nodes.items() if n.known_vulns and not n.isolated]
        if vulnerable and self.rng.random() < 0.5:
            return Action(ActionType.PATCH, self.agent_id, target_node=vulnerable[0],
                          params={"cve_id": nodes[vulnerable[0]].known_vulns[0]})

        # Priority 4: Monitor unmonitored nodes
        unmonitored = [nid for nid in nodes if nid not in self.monitored]
        if unmonitored:
            target = unmonitored[0]
            self.monitored.add(target)
            return Action(ActionType.MONITOR, self.agent_id, target_node=target)

        # Priority 5: Deploy honeypot early game
        if self.turn < 5:
            target = self.rng.choice(list(nodes.keys()))
            return Action(ActionType.DEPLOY_HONEYPOT, self.agent_id, target_node=target)

        return self._pass()


# ---------------------------------------------------------------------------
# LLM Agent Hook
# ---------------------------------------------------------------------------

class LLMAgent(BaseAgent):
    """
    Connects an LLM (e.g. Claude) as the decision-maker.
    The LLM receives a text summary of the observation and must
    output a structured action.

    Usage:
        agent = LLMAgent(agent_id="red-llm", team=Team.RED,
                         llm_fn=my_claude_call_fn)
        # llm_fn(prompt: str) -> str (JSON action)
    """

    def __init__(self, llm_fn, **kwargs):
        super().__init__(**kwargs)
        self.llm_fn      = llm_fn
        self.history:    list[dict] = []

    def _obs_to_prompt(self, obs: Observation) -> str:
        lines = [
            f"=== CYBER WARGAME — {self.team.value.upper()} AGENT ===",
            f"Turn: {obs.turn}",
            f"Your score: {obs.red_score if self.team == Team.RED else obs.blue_score:.1f}",
            f"Enemy score: {obs.blue_score if self.team == Team.RED else obs.red_score:.1f}",
            "",
            "VISIBLE NETWORK NODES:",
        ]
        for nid, n in obs.visible_nodes.items():
            status = []
            if n.compromised:   status.append("COMPROMISED")
            if n.isolated:      status.append("ISOLATED")
            if n.alert_level:   status.append(f"ALERT={n.alert_level}")
            if n.known_vulns:   status.append(f"VULNS={n.known_vulns}")
            lines.append(f"  {nid} [{n.node_type}] {' '.join(status)}")

        if obs.alerts:
            lines += ["", "ALERTS:"] + [f"  ! {a}" for a in obs.alerts]

        lines += [
            "",
            "Respond with a JSON action object:",
            '{ "action_type": "scan|exploit|lateral_move|exfiltrate|patch|isolate|...",',
            '  "target_node": "node_id",',
            '  "params": {} }',
        ]
        return "\n".join(lines)

    def act(self, obs: Observation) -> Action:
        import json
        prompt   = self._obs_to_prompt(obs)
        response = self.llm_fn(prompt)

        try:
            data        = json.loads(response)
            action_type = ActionType(data["action_type"])
            return Action(
                action_type  = action_type,
                actor_id     = self.agent_id,
                target_node  = data.get("target_node"),
                target_edge  = data.get("target_edge"),
                params       = data.get("params", {}),
            )
        except Exception as e:
            print(f"[LLMAgent] Parse error: {e}\nRaw: {response}")
            return self._pass()
