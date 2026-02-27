"""
Simulation Engine
-----------------
Orchestrates the Red vs Blue wargame:
  - Manages turn order (simultaneous or sequential)
  - Calls agents for actions
  - Resolves actions via ActionResolver
  - Applies effects to the Network
  - Tracks history and determines win conditions
"""

from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Optional

from env.network import Network, Team
from env.actions import Action, ActionResolver, Outcome, ActionType
from env.observation import ObservationBuilder, Observation
from agents.agents import BaseAgent


# ---------------------------------------------------------------------------
# Turn Record
# ---------------------------------------------------------------------------

@dataclass
class TurnRecord:
    turn:         int
    red_action:   Action
    red_outcome:  Outcome
    blue_action:  Action
    blue_outcome: Outcome
    red_score:    float
    blue_score:   float
    alerts:       list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"━━━ Turn {self.turn} ━━━",
            f"  🔴 {self.red_action}  →  {self.red_outcome}",
            f"  🔵 {self.blue_action}  →  {self.blue_outcome}",
            f"  Score  Red={self.red_score:.1f}  Blue={self.blue_score:.1f}",
        ]
        if self.alerts:
            lines += [f"  ⚠ {a}" for a in self.alerts]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Win Condition
# ---------------------------------------------------------------------------

@dataclass
class WinCondition:
    """Checked after each turn. First satisfied ends the game."""
    max_turns:          int   = 30
    red_score_thresh:   float = 20.0   # red wins if score ≥ this
    blue_score_thresh:  float = 0.0    # blue wins if red score falls ≤ this
    exfil_thresh:       float = 0.8    # red wins if any node fully exfiltrated

    def check(self, network: Network, turn: int) -> Optional[Team]:
        if network.red_score() >= self.red_score_thresh:
            return Team.RED
        if turn >= self.max_turns:
            # Whoever has more score wins at time limit
            return Team.RED if network.red_score() > network.blue_score() * 0.4 else Team.BLUE
        for n in network.all_nodes():
            if n.state.data_exfil >= self.exfil_thresh:
                return Team.RED
        return None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SimulationEngine:
    """
    Main game loop.

    mode="sequential"  — Red acts, then Blue acts (default)
    mode="simultaneous" — Both act simultaneously (more realistic)
    """

    def __init__(
        self,
        network:       Network,
        red_agent:     BaseAgent,
        blue_agent:    BaseAgent,
        win_condition: WinCondition = None,
        mode:          str = "sequential",
        rng:           random.Random = None,
        verbose:       bool = True,
    ):
        self.network       = network
        self.red_agent     = red_agent
        self.blue_agent    = blue_agent
        self.win_condition = win_condition or WinCondition()
        self.mode          = mode
        self.rng           = rng or random.Random()
        self.verbose       = verbose

        # Seed obs builder with any nodes already compromised by red at game start,
        # plus their immediate neighbors (recon from entry point)
        initial_red = [n.id for n in network.all_nodes() if n.state.compromised]
        initial_scanned = set(initial_red)
        for nid in initial_red:
            for neighbor in network.neighbors(nid):
                initial_scanned.add(neighbor.id)
        self.resolver    = ActionResolver(rng=self.rng)
        self.obs_builder = ObservationBuilder(initial_red_nodes=list(initial_scanned))
        self.history:   list[TurnRecord] = []
        self.turn:      int = 0
        self.winner:    Optional[Team] = None

    # ------------------------------------------------------------------
    # Effect Application
    # ------------------------------------------------------------------

    def _apply_effects(self, outcome: Outcome, team: Team):
        fx = outcome.effects
        net = self.network

        if "compromise_node" in fx:
            node = net.node(fx["compromise_node"])
            node.state.compromised = True
            node.state.owner = Team.RED
            self.obs_builder.add_red_discovery(node.id)

        if "mark_exploited" in fx:
            node_id, cve = fx.get("mark_exploited_node"), fx["mark_exploited"]
            # find the vuln in target node (from action)
            target = outcome.action.target_node
            if target:
                vuln = net.node(target).has_vuln(cve)
                if vuln:
                    vuln.exploited = True

        if "exfil_delta" in fx:
            node_id, delta = fx["exfil_delta"]
            net.node(node_id).state.data_exfil = min(1.0,
                net.node(node_id).state.data_exfil + delta)

        if "alert_delta" in fx:
            target = outcome.action.target_node
            if target:
                node = net.node(target)
                node.state.alert_level = min(100, node.state.alert_level + fx["alert_delta"])

        if "alert_node" in fx and "alert_delta" in fx:
            node = net.node(fx["alert_node"])
            node.state.alert_level = min(100, node.state.alert_level + fx["alert_delta"])

        if "patch_vuln" in fx:
            node_id, cve = fx["patch_vuln"]
            vuln = net.node(node_id).has_vuln(cve)
            if vuln:
                vuln.exploited = True   # can't be exploited anymore

        if "patch_level_up" in fx:
            node = net.node(fx["patch_level_up"])
            node.state.patch_level = min(5, node.state.patch_level + 1)

        if "isolate" in fx:
            net.node(fx["isolate"]).state.isolated = True

        if "restore" in fx:
            node = net.node(fx["restore"])
            node.state.compromised  = False
            node.state.owner        = Team.BLUE
            node.state.data_exfil   = 0.0
            node.state.alert_level  = 0
            node.state.isolated     = False
            for v in node.vulnerabilities:
                v.exploited = False

        if "honeypot" in fx:
            net.node(fx["honeypot"]).state.honeypot = True

        if "decoy" in fx:
            net.node(fx["decoy"]).state.decoy = True

        if "monitor" in fx:
            info = fx["monitor"]
            if info.get("node"):
                # mark the node's edges as monitored
                for src, dst in self.network.graph.edges():
                    if dst == info["node"]:
                        edge = self.network.edge(src, dst)
                        if edge:
                            edge.monitored = True
            if info.get("edge"):
                edge = self.network.edge(*info["edge"])
                if edge:
                    edge.monitored = True

        if "block_edge" in fx:
            src, dst = fx["block_edge"]
            self.network.graph.remove_edge(src, dst)

        if "hunt_result" in fx:
            node_id, found = fx["hunt_result"]
            if found and fx.get("alert_reset"):
                net.node(node_id).state.alert_level = 0

        if "ddos" in fx:
            node = net.node(fx["ddos"])
            for svc in node.services:
                svc.running = False

        if "persist" in fx:
            # Persistence means future restores have 30% chance to fail (tracked in memory)
            # For now just log it — engine extensions can check this
            pass

        if "priv_esc" in fx:
            # Priv esc could unlock more actions; track in state
            pass

        if outcome.alerts:
            self.obs_builder.add_alerts(outcome.alerts)

    # ------------------------------------------------------------------
    # Turn Execution
    # ------------------------------------------------------------------

    def step(self) -> Optional[TurnRecord]:
        """Execute one full turn. Returns TurnRecord or None if game over."""
        if self.winner is not None:
            return None

        self.turn += 1
        self.obs_builder.clear_turn_alerts()

        # Build observations
        red_obs  = self.obs_builder.build_red_obs(self.network, self.turn)
        blue_obs = self.obs_builder.build_blue_obs(self.network, self.turn)

        # Get actions
        red_action  = self.red_agent.act(red_obs)
        blue_action = self.blue_agent.act(blue_obs)

        # Resolve
        red_outcome  = self.resolver.resolve(red_action, self.network)
        blue_outcome = self.resolver.resolve(blue_action, self.network)

        # Apply effects (blue first in sequential so red sees fresh state in obs, not effects)
        if self.mode == "sequential":
            self._apply_effects(red_outcome, Team.RED)
            self._apply_effects(blue_outcome, Team.BLUE)
        else:
            # Simultaneous: apply both, order random
            order = [(red_outcome, Team.RED), (blue_outcome, Team.BLUE)]
            self.rng.shuffle(order)
            for outcome, team in order:
                self._apply_effects(outcome, team)

        # Build turn record
        all_alerts = (red_outcome.alerts or []) + (blue_outcome.alerts or [])
        record = TurnRecord(
            turn=self.turn,
            red_action=red_action, red_outcome=red_outcome,
            blue_action=blue_action, blue_outcome=blue_outcome,
            red_score=self.network.red_score(),
            blue_score=self.network.blue_score(),
            alerts=all_alerts,
        )
        self.history.append(record)

        if self.verbose:
            print(record.summary())

        # Check win condition
        self.winner = self.win_condition.check(self.network, self.turn)
        if self.winner and self.verbose:
            print(f"\n🏆 GAME OVER — {self.winner.value.upper()} WINS at turn {self.turn}")

        return record

    def run(self, max_turns: int = None) -> Team:
        """Run the full game to completion."""
        limit = max_turns or self.win_condition.max_turns
        while self.winner is None and self.turn < limit:
            self.step()
        return self.winner or Team.BLUE

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def score_history(self) -> dict:
        return {
            "turns":      [r.turn for r in self.history],
            "red_scores": [r.red_score for r in self.history],
            "blue_scores": [r.blue_score for r in self.history],
        }

    def action_breakdown(self) -> dict:
        red_actions  = {}
        blue_actions = {}
        for r in self.history:
            at = r.red_action.action_type.value
            red_actions[at] = red_actions.get(at, 0) + 1
            at = r.blue_action.action_type.value
            blue_actions[at] = blue_actions.get(at, 0) + 1
        return {"red": red_actions, "blue": blue_actions}

    def final_report(self) -> str:
        lines = [
            "=" * 60,
            f"FINAL REPORT — {self.network.name}",
            "=" * 60,
            f"Turns played:       {self.turn}",
            f"Winner:             {(self.winner or Team.BLUE).value.upper()}",
            f"Red final score:    {self.network.red_score():.2f}",
            f"Blue final score:   {self.network.blue_score():.2f}",
            f"Nodes compromised:  {len(self.network.compromised_nodes())} / {len(self.network.all_nodes())}",
            "",
            "Node Status:",
        ]
        for node in self.network.all_nodes():
            s = node.state
            lines.append(
                f"  {node.id:<20} owner={s.owner.value:<8} "
                f"compromised={str(s.compromised):<6} "
                f"exfil={s.data_exfil*100:.0f}%  "
                f"alert={s.alert_level}"
            )
        lines += ["", "Action Breakdown:"]
        ab = self.action_breakdown()
        lines.append(f"  Red:  {ab['red']}")
        lines.append(f"  Blue: {ab['blue']}")
        return "\n".join(lines)
