"""
Observation System
------------------
Agents don't see the full Network — they receive filtered Observations
based on what they've discovered / what's been monitored.

Red sees:    only nodes it has scanned or compromised
Blue sees:   all nodes, but can't see red's plans; sees alerts & anomalies
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any
from env.network import Network, Node, Team


@dataclass
class NodeObservation:
    """What an agent knows about a single node."""
    node_id:       str
    node_type:     str
    owner:         str
    compromised:   bool
    isolated:      bool
    services:      list[str]
    known_vulns:   list[str]       # CVEs the agent knows about
    alert_level:   Optional[int]   # only visible to blue
    data_exfil:    Optional[float] # only visible to blue
    honeypot:      Optional[bool]  # only visible to blue


@dataclass
class Observation:
    """
    What a specific team can observe on a given turn.
    """
    team:             Team
    turn:             int
    visible_nodes:    dict[str, NodeObservation]
    alerts:           list[str]               = field(default_factory=list)
    red_score:        float                   = 0.0
    blue_score:       float                   = 0.0
    known_edges:      list[tuple]             = field(default_factory=list)
    extra:            dict[str, Any]          = field(default_factory=dict)

    def node(self, node_id: str) -> Optional[NodeObservation]:
        return self.visible_nodes.get(node_id)

    def compromised_nodes(self) -> list[str]:
        return [nid for nid, n in self.visible_nodes.items() if n.compromised]

    def exploitable_nodes(self) -> list[str]:
        return [nid for nid, n in self.visible_nodes.items()
                if n.known_vulns and not n.compromised and not n.isolated]


class ObservationBuilder:
    """Builds partial observations per team from ground-truth Network."""

    def __init__(self, initial_red_nodes: list = None):
        self._red_known: set  = set(initial_red_nodes or [])
        self._blue_alerts: list = []

    def add_red_discovery(self, node_id: str):
        self._red_known.add(node_id)

    def add_alerts(self, alerts: list[str]):
        self._blue_alerts.extend(alerts)

    def clear_turn_alerts(self):
        self._blue_alerts = []

    def build_red_obs(self, network: Network, turn: int) -> Observation:
        visible = {}
        edges   = []

        # Red sees: nodes it has scanned/known + nodes directly reachable from them
        visible_ids = set(self._red_known)
        for node_id in list(visible_ids):
            # Expand visibility to neighbors of all known nodes
            try:
                for neighbor in network.neighbors(node_id):
                    visible_ids.add(neighbor.id)
            except Exception:
                pass

        for node in network.all_nodes():
            if node.id not in visible_ids:
                continue
            # For nodes red has only "seen from a distance" (neighbor but not scanned),
            # show limited info
            fully_known = node.id in self._red_known or node.state.compromised
            visible[node.id] = NodeObservation(
                node_id=node.id,
                node_type=node.node_type.value,
                owner=node.state.owner.value,
                compromised=node.state.compromised,
                isolated=node.state.isolated,
                services=[str(s) for s in node.services if s.running] if fully_known else [],
                known_vulns=[v.cve_id for v in node.exploitable_vulns()] if fully_known else [],
                alert_level=None,
                data_exfil=node.state.data_exfil if node.state.compromised else None,
                honeypot=None,
            )

        for src, dst in network.graph.edges():
            if src in visible_ids or dst in visible_ids:
                edges.append((src, dst))

        return Observation(
            team=Team.RED, turn=turn,
            visible_nodes=visible,
            alerts=[],
            red_score=network.red_score(),
            blue_score=network.blue_score(),
            known_edges=edges,
        )

    def build_blue_obs(self, network: Network, turn: int) -> Observation:
        """Blue sees ALL nodes but can't identify red's future intentions."""
        visible = {}
        for node in network.all_nodes():
            visible[node.id] = NodeObservation(
                node_id=node.id,
                node_type=node.node_type.value,
                owner=node.state.owner.value,
                compromised=node.state.compromised,
                isolated=node.state.isolated,
                services=[str(s) for s in node.services if s.running],
                known_vulns=[v.cve_id for v in node.exploitable_vulns()],
                alert_level=node.state.alert_level,
                data_exfil=node.state.data_exfil,
                honeypot=node.state.honeypot,
            )

        edges = list(network.graph.edges())

        obs = Observation(
            team=Team.BLUE, turn=turn,
            visible_nodes=visible,
            alerts=list(self._blue_alerts),
            red_score=network.red_score(),
            blue_score=network.blue_score(),
            known_edges=edges,
        )
        return obs
