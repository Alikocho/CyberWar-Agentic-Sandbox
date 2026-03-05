"""
CyberWar Network Environment
-----------------------------
Models a network as a directed graph of Nodes connected by Edges.
Each Node has services, vulnerabilities, and ownership state.
"""

from __future__ import annotations
import networkx as nx
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import copy
import random


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

class Team(Enum):
    NEUTRAL = "neutral"
    RED     = "red"      # attacker
    BLUE    = "blue"     # defender


class NodeType(Enum):
    WORKSTATION  = "workstation"
    SERVER       = "server"
    ROUTER       = "router"
    FIREWALL     = "firewall"
    DATABASE     = "database"
    DMZ          = "dmz"


@dataclass
class Vulnerability:
    cve_id:    str
    cvss:      float          # 0–10
    service:   str
    exploited: bool = False

    def __repr__(self):
        flag = "✓" if self.exploited else "○"
        return f"[{flag}{self.cve_id} cvss={self.cvss}]"


@dataclass
class Service:
    name:    str              # e.g. "ssh", "http", "smb"
    port:    int
    version: str
    running: bool = True

    def __repr__(self):
        state = "UP" if self.running else "DOWN"
        return f"{self.name}:{self.port}/{state}"


@dataclass
class NodeState:
    """Runtime mutable state of a node."""
    owner:          Team          = Team.NEUTRAL
    compromised:    bool          = False
    isolated:       bool          = False   # blue can quarantine
    honeypot:       bool          = False
    decoy:          bool          = False
    patch_level:    int           = 0       # 0=unpatched, higher=more patched
    alert_level:    int           = 0       # blue's suspicion 0-100
    data_exfil:     float         = 0.0    # % of data stolen


@dataclass
class Node:
    id:             str
    label:          str
    node_type:      NodeType
    services:       list[Service]        = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    value:          int                  = 1     # strategic value 1-10
    state:          NodeState            = field(default_factory=NodeState)

    def has_vuln(self, cve_id: str) -> Optional[Vulnerability]:
        return next((v for v in self.vulnerabilities if v.cve_id == cve_id), None)

    def exploitable_vulns(self) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if not v.exploited]

    def is_accessible(self) -> bool:
        return not self.state.isolated

    def __repr__(self):
        owner_icon = {"neutral": "○", "red": "🔴", "blue": "🔵"}[self.state.owner.value]
        return f"Node({self.id}|{self.node_type.value}|{owner_icon})"


@dataclass
class Edge:
    source:     str
    target:     str
    bandwidth:  int   = 100     # Mbps
    encrypted:  bool  = False
    monitored:  bool  = False   # blue can monitor edges


# ---------------------------------------------------------------------------
# The Network
# ---------------------------------------------------------------------------

class Network:
    """
    The game board. A directed graph of Nodes and Edges.
    Maintains ground truth — agents receive partial observations.
    """

    def __init__(self, name: str = "unnamed"):
        self.name  = name
        self.graph = nx.DiGraph()
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple, Edge] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def add_node(self, node: Node) -> Network:
        self._nodes[node.id] = node
        self.graph.add_node(node.id, data=node)
        return self

    def add_edge(self, edge: Edge) -> Network:
        self._edges[(edge.source, edge.target)] = edge
        self.graph.add_edge(edge.source, edge.target, data=edge)
        return self

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def node(self, node_id: str) -> Node:
        return self._nodes[node_id]

    def edge(self, src: str, dst: str) -> Optional[Edge]:
        return self._edges.get((src, dst))

    def neighbors(self, node_id: str) -> list[Node]:
        return [self._nodes[n] for n in self.graph.successors(node_id)]

    def all_nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def red_nodes(self) -> list[Node]:
        return [n for n in self._nodes.values() if n.state.owner == Team.RED]

    def blue_nodes(self) -> list[Node]:
        return [n for n in self._nodes.values() if n.state.owner == Team.BLUE]

    def compromised_nodes(self) -> list[Node]:
        return [n for n in self._nodes.values() if n.state.compromised]

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def red_score(self) -> float:
        """Total value captured + exfil progress."""
        score = 0.0
        for n in self.compromised_nodes():
            score += n.value
            score += n.state.data_exfil * n.value
        return score

    def blue_score(self) -> float:
        """Nodes not compromised, weighted by value."""
        score = 0.0
        for n in self.all_nodes():
            if not n.state.compromised:
                score += n.value
        return score

    def __repr__(self):
        return (
            f"Network('{self.name}' "
            f"nodes={len(self._nodes)} "
            f"edges={len(self._edges)} "
            f"compromised={len(self.compromised_nodes())})"
        )
