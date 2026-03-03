#!/usr/bin/env python3
"""
CyberWar Sandbox — Flask Web Server
=====================================
Serves the web UI and exposes a JSON API for running simulations.

Usage:
    python app.py                    # starts on http://localhost:5000
    python app.py --port 8080        # custom port
    python app.py --debug            # hot-reload dev mode
"""

import argparse
import json
import os
import random
import sys
import threading
import time
import webbrowser
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, request, render_template, send_from_directory

from env.network import Team
from engine.engine import SimulationEngine, WinCondition
from agents.agents import (
    RandomRedAgent, HeuristicRedAgent,
    RandomBlueAgent, HeuristicBlueAgent,
)
from agents.human_agent import (
    HumanRedAgent, HumanBlueAgent,
    compute_available_actions,
)
from scenarios.scenarios import corporate_network, ics_network, cloud_network, govdef_network
from env.actions import Action, ActionType

# ─── Constants ───────────────────────────────────────────────────────────────

# When running as a PyInstaller bundle, data files live in sys._MEIPASS
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent

TEMPLATE_P = BASE_DIR / "cyberwar_ui_template.html"

SCENARIOS = {
    "corporate": {
        "fn":          corporate_network,
        "name":        "Corporate Headquarters",
        "description": "9-node enterprise network — IT perimeter, AD, DBs, workstations",
        "difficulty":  "Beginner",
        "nodes":       9,
    },
    "ics": {
        "fn":          ics_network,
        "name":        "Industrial Control System",
        "description": "Air-gapped OT/ICS environment — PLCs, HMI, historian under Purdue model",
        "difficulty":  "Intermediate",
        "nodes":       7,
    },
    "cloud": {
        "fn":          cloud_network,
        "name":        "Cloud-Native SaaS Platform",
        "description": "AWS-style cloud: API gateway, Lambda, EC2, RDS, S3, IAM, VPC",
        "difficulty":  "Intermediate",
        "nodes":       7,
    },
    "govdef": {
        "fn":          govdef_network,
        "name":        "Government / Defense SCIF",
        "description": "NIPR→SIPR cross-domain solution with classified crown-jewel systems",
        "difficulty":  "Advanced",
        "nodes":       8,
    },
}

RED_AGENTS = {
    "random":    RandomRedAgent,
    "heuristic": HeuristicRedAgent,
}

BLUE_AGENTS = {
    "random":    RandomBlueAgent,
    "heuristic": HeuristicBlueAgent,
}

# ─── Game data capture ───────────────────────────────────────────────────────

def capture_node_states(network):
    states = {}
    for node in network.all_nodes():
        states[node.id] = {
            "owner":       node.state.owner.value,
            "compromised": node.state.compromised,
            "isolated":    node.state.isolated,
            "alert_level": node.state.alert_level,
            "data_exfil":  round(node.state.data_exfil, 3),
            "patch_level": node.state.patch_level,
            "honeypot":    node.state.honeypot,
        }
    return states


def run_simulation(scenario_key, red_type, blue_type, max_turns, seed):
    """Run a full simulation and return serialisable game data."""
    rng       = random.Random(seed)
    scenario  = SCENARIOS[scenario_key]
    network, start_node = scenario["fn"]()

    red  = RED_AGENTS[red_type] (agent_id="red-agent",  team=Team.RED,  start_node=start_node, rng=rng)
    blue = BLUE_AGENTS[blue_type](agent_id="blue-agent", team=Team.BLUE, rng=rng)

    engine = SimulationEngine(
        network=network, red_agent=red, blue_agent=blue,
        win_condition=WinCondition(max_turns=max_turns),
        verbose=False, rng=rng,
    )

    snapshots = [capture_node_states(network)]
    history   = []

    while engine.winner is None and engine.turn < max_turns:
        r = engine.step()
        if r:
            history.append({
                "turn":             r.turn,
                "red_action_type":  r.red_action.action_type.value,
                "red_target":       r.red_action.target_node,
                "red_status":       r.red_outcome.status.value,
                "red_msg":          r.red_outcome.message,
                "red_reward":       round(r.red_outcome.reward, 2),
                "blue_action_type": r.blue_action.action_type.value,
                "blue_target":      r.blue_action.target_node,
                "blue_status":      r.blue_outcome.status.value,
                "blue_msg":         r.blue_outcome.message,
                "blue_reward":      round(r.blue_outcome.reward, 2),
                "red_score":        round(r.red_score, 2),
                "blue_score":       round(r.blue_score, 2),
                "alerts":           r.alerts,
            })
            snapshots.append(capture_node_states(network))

    nodes = []
    for node in network.all_nodes():
        nodes.append({
            "id":              node.id,
            "label":           node.label,
            "type":            node.node_type.value,
            "value":           node.value,
            "services":        [str(s) for s in node.services],
            "vulnerabilities": [{"cve": v.cve_id, "cvss": v.cvss} for v in node.vulnerabilities],
        })

    edges = []
    for src, dst in network.graph.edges():
        e = network.edge(src, dst)
        edges.append({"source": src, "target": dst, "monitored": e.monitored if e else False})

    winner = (engine.winner or Team.BLUE).value
    return {
        "scenario":    network.name,
        "scenario_key": scenario_key,
        "winner":      winner,
        "total_turns": engine.turn,
        "nodes":       nodes,
        "edges":       edges,
        "history":     history,
        "snapshots":   snapshots,
        "config": {
            "red":   red_type,
            "blue":  blue_type,
            "seed":  seed,
            "turns": max_turns,
        },
    }

# ─── Flask app ───────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

@app.route("/")
def index():
    """Main SPA entrypoint."""
    return render_template("index.html")


@app.route("/api/scenarios")
def api_scenarios():
    """List available scenarios with metadata."""
    result = {}
    for key, meta in SCENARIOS.items():
        result[key] = {k: v for k, v in meta.items() if k != "fn"}
    return jsonify(result)


@app.route("/api/agents")
def api_agents():
    """List available agent types."""
    return jsonify({
        "red":  list(RED_AGENTS.keys()),
        "blue": list(BLUE_AGENTS.keys()),
    })


@app.route("/api/run", methods=["POST"])
def api_run():
    """
    Run a simulation. Request body (JSON):
        scenario  : str   corporate | ics | cloud | govdef
        red       : str   random | heuristic
        blue      : str   random | heuristic
        turns     : int   1-50
        seed      : int   optional, random if omitted
    Returns full game data JSON.
    """
    body = request.get_json(force=True, silent=True) or {}

    scenario = body.get("scenario", "corporate")
    red      = body.get("red",      "heuristic")
    blue     = body.get("blue",     "heuristic")
    turns    = int(body.get("turns", 20))
    seed     = body.get("seed") or random.randint(0, 999999)

    # Validate inputs
    if scenario not in SCENARIOS:
        return jsonify({"error": f"Unknown scenario '{scenario}'"}), 400
    if red not in RED_AGENTS:
        return jsonify({"error": f"Unknown red agent '{red}'"}), 400
    if blue not in BLUE_AGENTS:
        return jsonify({"error": f"Unknown blue agent '{blue}'"}), 400
    turns = max(1, min(50, turns))

    try:
        game_data = run_simulation(scenario, red, blue, turns, seed)
        return jsonify(game_data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/replay", methods=["POST"])
def api_replay():
    """
    Run a simulation and return a self-contained HTML replay file.
    Same request body as /api/run.
    Returns: text/html
    """
    body = request.get_json(force=True, silent=True) or {}

    scenario = body.get("scenario", "corporate")
    red      = body.get("red",      "heuristic")
    blue     = body.get("blue",     "heuristic")
    turns    = int(body.get("turns", 20))
    seed     = body.get("seed") or random.randint(0, 999999)

    if scenario not in SCENARIOS:
        return jsonify({"error": f"Unknown scenario '{scenario}'"}), 400

    if not TEMPLATE_P.exists():
        return jsonify({"error": "cyberwar_ui_template.html not found on server"}), 500

    game_data = run_simulation(scenario, red, blue, turns, seed)
    html = TEMPLATE_P.read_text()
    html = html.replace("GAME_DATA_PLACEHOLDER", json.dumps(game_data, separators=(",", ":")))

    from flask import Response
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition":
                             f'attachment; filename="cyberwar_{scenario}_{seed}.html"'})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


# ─── Live Game Sessions ───────────────────────────────────────────────────────

import uuid
from engine.engine import SimulationEngine, WinCondition, TurnRecord

_game_sessions: dict = {}   # session_id -> GameSession


class GameSession:
    """
    Manages one live human-vs-AI game.
    The human submits an action via the API; we load it into the HumanAgent
    then call engine.step() synchronously.
    """

    def __init__(self, scenario_key: str, human_team: str, ai_type: str,
                 max_turns: int, seed: int):
        self.session_id  = str(uuid.uuid4())[:8]
        self.human_team  = human_team          # "red" or "blue"
        self.max_turns   = max_turns
        self.seed        = seed
        self.rng         = random.Random(seed)

        scenario = SCENARIOS[scenario_key]
        self.network, start_node = scenario["fn"]()

        # Build agents — one human, one AI
        if human_team == "red":
            self.human_agent = HumanRedAgent(
                agent_id="human", team=Team.RED, start_node=start_node, rng=self.rng)
            ai_cls = RED_AGENTS.get(ai_type, HeuristicRedAgent)
            # AI plays blue
            self.ai_agent = HeuristicBlueAgent(
                agent_id="ai", team=Team.BLUE, rng=self.rng) if ai_type == "heuristic" \
                else RandomBlueAgent(agent_id="ai", team=Team.BLUE, rng=self.rng)
            red_agent, blue_agent = self.human_agent, self.ai_agent
        else:
            self.human_agent = HumanBlueAgent(
                agent_id="human", team=Team.BLUE, rng=self.rng)
            self.ai_agent = HeuristicRedAgent(
                agent_id="ai", team=Team.RED, start_node=start_node, rng=self.rng) \
                if ai_type == "heuristic" \
                else RandomRedAgent(agent_id="ai", team=Team.RED,
                                    start_node=start_node, rng=self.rng)
            red_agent, blue_agent = self.ai_agent, self.human_agent

        self.engine = SimulationEngine(
            network=self.network,
            red_agent=red_agent,
            blue_agent=blue_agent,
            win_condition=WinCondition(max_turns=max_turns),
            verbose=False,
            rng=self.rng,
        )

        # Give Red initial visibility of the entry node + its immediate neighbours.
        # The engine only seeds obs_builder from already-compromised nodes (none at
        # game start), so without this Red's opening observation is completely empty.
        self.engine.obs_builder.add_red_discovery(start_node)
        for n in self.network.neighbors(start_node):
            self.engine.obs_builder.add_red_discovery(n.id)

        self.last_record = None

    # ── Serialisation helpers ─────────────────────────────────────────────────

    def _serialize_obs(self, obs) -> dict:
        return {
            "team":  obs.team.value,
            "turn":  obs.turn,
            "red_score":  round(obs.red_score, 2),
            "blue_score": round(obs.blue_score, 2),
            "alerts": obs.alerts,
            "known_edges": [[s, d] for s, d in obs.known_edges],
            "visible_nodes": {
                nid: {
                    "node_id":     n.node_id,
                    "node_type":   n.node_type,
                    "owner":       n.owner,
                    "compromised": n.compromised,
                    "isolated":    n.isolated,
                    "services":    n.services,
                    "known_vulns": n.known_vulns,
                    "alert_level": n.alert_level,
                    "data_exfil":  n.data_exfil,
                    "honeypot":    n.honeypot,
                }
                for nid, n in obs.visible_nodes.items()
            },
        }

    def _serialize_record(self, r: TurnRecord) -> dict:
        return {
            "turn":             r.turn,
            "red_action_type":  r.red_action.action_type.value,
            "red_target":       r.red_action.target_node,
            "red_status":       r.red_outcome.status.value,
            "red_msg":          r.red_outcome.message,
            "red_reward":       round(r.red_outcome.reward, 2) if hasattr(r.red_outcome, "reward") else 0,
            "blue_action_type": r.blue_action.action_type.value,
            "blue_target":      r.blue_action.target_node,
            "blue_status":      r.blue_outcome.status.value,
            "blue_msg":         r.blue_outcome.message,
            "blue_reward":      round(r.blue_outcome.reward, 2) if hasattr(r.blue_outcome, "reward") else 0,
            "red_score":        round(r.red_score, 2),
            "blue_score":       round(r.blue_score, 2),
            "alerts":           r.alerts,
        }

    def _network_snapshot(self) -> dict:
        states = {}
        for node in self.network.all_nodes():
            states[node.id] = {
                "owner":       node.state.owner.value,
                "compromised": node.state.compromised,
                "isolated":    node.state.isolated,
                "alert_level": node.state.alert_level,
                "data_exfil":  round(node.state.data_exfil, 3),
                "patch_level": node.state.patch_level,
                "honeypot":    node.state.honeypot,
            }
        return states

    # ── Public API ────────────────────────────────────────────────────────────

    def get_initial_state(self) -> dict:
        """Called once after session creation — returns everything the UI needs."""
        obs = (self.engine.obs_builder.build_red_obs(self.network, 0)
               if self.human_team == "red"
               else self.engine.obs_builder.build_blue_obs(self.network, 0))

        nodes_meta = []
        for node in self.network.all_nodes():
            nodes_meta.append({
                "id":              node.id,
                "label":           node.label,
                "type":            node.node_type.value,
                "value":           node.value,
                "services":        [str(s) for s in node.services],
                "vulnerabilities": [{"cve": v.cve_id, "cvss": v.cvss}
                                    for v in node.vulnerabilities],
            })

        edges_meta = []
        for src, dst in self.network.graph.edges():
            e = self.network.edge(src, dst)
            edges_meta.append({"source": src, "target": dst,
                                "monitored": e.monitored if e else False})

        return {
            "session_id":    self.session_id,
            "scenario":      self.network.name,
            "human_team":    self.human_team,
            "max_turns":     self.max_turns,
            "turn":          0,
            "game_over":     False,
            "winner":        None,
            "nodes":         nodes_meta,
            "edges":         edges_meta,
            "snapshot":      self._network_snapshot(),
            "observation":   self._serialize_obs(obs),
            "available_actions": compute_available_actions(obs),
            "last_record":   None,
        }

    def step(self, action_dict: dict) -> dict:
        """
        Load the human's action, run one engine turn, return new state.
        action_dict: { "action_type": str, "target_node": str|null,
                       "params": dict }
        """
        # Build Action object
        # Note: JS sends "target" and "cve"/"from_node" as top-level keys,
        # not "target_node" or a nested "params" dict.
        try:
            atype = ActionType(action_dict.get("action_type", "pass"))
        except ValueError:
            atype = ActionType.PASS

        target_node = action_dict.get("target") or action_dict.get("target_node") or None
        from_node   = action_dict.get("from_node") or None
        cve         = action_dict.get("cve") or None

        params = {}
        if from_node:
            params["from_node"] = from_node
        if cve:
            params["cve_id"] = cve

        action = Action(
            action_type  = atype,
            actor_id     = "human",
            target_node  = target_node,
            params       = params,
        )
        self.human_agent.load_action(action)

        # Run one engine turn
        record = self.engine.step()
        self.last_record = record

        # Build fresh observation for the human
        turn = self.engine.turn
        obs = (self.engine.obs_builder.build_red_obs(self.network, turn)
               if self.human_team == "red"
               else self.engine.obs_builder.build_blue_obs(self.network, turn))

        game_over = self.engine.winner is not None
        winner    = self.engine.winner.value if self.engine.winner else None

        return {
            "session_id":        self.session_id,
            "turn":              turn,
            "done":              game_over,   # JS checks "done"
            "game_over":         game_over,
            "winner":            winner,
            "human_team":        self.human_team,
            "snapshot":          self._network_snapshot(),
            "observation":       self._serialize_obs(obs),
            "available_actions": compute_available_actions(obs) if not game_over else [],
            "last_record":       self._serialize_record(record) if record else None,
        }


# ─── Live Game Endpoints ──────────────────────────────────────────────────────

@app.route("/api/game/new", methods=["POST"])
def api_game_new():
    """
    Create a new live human-vs-AI game session.
    Body:
        scenario    : str  corporate | ics | cloud | govdef
        human_team  : str  red | blue
        ai          : str  random | heuristic
        turns       : int  1-50
        seed        : int  optional
    Returns initial game state.
    """
    body = request.get_json(force=True, silent=True) or {}

    scenario   = body.get("scenario",   "corporate")
    human_team = body.get("human_team", "red")
    ai_type    = body.get("ai",         "heuristic")
    turns      = max(1, min(50, int(body.get("turns", 20))))
    seed       = body.get("seed") or random.randint(0, 999999)

    if scenario not in SCENARIOS:
        return jsonify({"error": f"Unknown scenario '{scenario}'"}), 400
    if human_team not in ("red", "blue"):
        return jsonify({"error": "human_team must be 'red' or 'blue'"}), 400

    try:
        session = GameSession(scenario, human_team, ai_type, turns, seed)
        _game_sessions[session.session_id] = session
        return jsonify(session.get_initial_state())
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/game/action", methods=["POST"])
def api_game_action():
    """
    Submit the human player's action and advance one turn.
    Body:
        session_id  : str
        action_type : str  e.g. "scan", "exploit", "patch" …
        target_node : str  node id (or null for PASS)
        params      : dict  optional  e.g. {"cve_id": "CVE-2022-30190", "from_node": "nipr_server"}
    Returns updated game state.
    """
    body = request.get_json(force=True, silent=True) or {}
    sid  = body.get("session_id")

    session = _game_sessions.get(sid)
    if session is None:
        return jsonify({"error": "Session not found or expired"}), 404

    if session.engine.winner is not None:
        return jsonify({"error": "Game is already over"}), 400

    try:
        result = session.step(body)
        # Clean up finished sessions after a delay (keep for replay)
        return jsonify(result)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/game/state/<session_id>")
def api_game_state(session_id):
    """Get current state of a live game (for reconnects)."""
    session = _game_sessions.get(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404
    state = session.get_initial_state()
    state["turn"] = session.engine.turn
    state["game_over"] = session.engine.winner is not None
    state["winner"] = session.engine.winner.value if session.engine.winner else None
    return jsonify(state)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberWar Web UI Server")
    parser.add_argument("--port",  type=int, default=5000, help="Port to listen on (default 5000)")
    parser.add_argument("--host",  default="127.0.0.1",    help="Host to bind (default 127.0.0.1)")
    parser.add_argument("--debug", action="store_true",    help="Enable Flask debug/hot-reload")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print(f"\n  ╔══════════════════════════════════════╗")
    print(f"  ║   CYBERWAR SANDBOX  — Web UI         ║")
    print(f"  ╚══════════════════════════════════════╝")
    print(f"\n  Listening on  {url}")
    print(f"  Press Ctrl+C to quit\n")

    if not args.no_browser and not args.debug:
        # Open browser after a short delay to let Flask start
        def _open():
            time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
