#!/usr/bin/env python3
"""
generate_ui.py
--------------
Run a CyberWar game and produce a self-contained battle replay HTML file.

Usage:
    python generate_ui.py
    python generate_ui.py --scenario ics --red heuristic --blue random --seed 42 --out replay.html
"""

import argparse
import random
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from env.network import Team
from engine.engine import SimulationEngine, WinCondition
from agents.agents import HeuristicRedAgent, HeuristicBlueAgent, RandomRedAgent, RandomBlueAgent
from scenarios.scenarios import corporate_network, ics_network, cloud_network

SCENARIOS = { 'corporate': corporate_network, 'ics': ics_network, 'cloud': cloud_network }
RED_AGENTS  = { 'heuristic': HeuristicRedAgent, 'random': RandomRedAgent }
BLUE_AGENTS = { 'heuristic': HeuristicBlueAgent, 'random': RandomBlueAgent }

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'cyberwar_ui_template.html')


def capture_node_states(network):
    states = {}
    for node in network.all_nodes():
        states[node.id] = {
            'owner':       node.state.owner.value,
            'compromised': node.state.compromised,
            'isolated':    node.state.isolated,
            'alert_level': node.state.alert_level,
            'data_exfil':  round(node.state.data_exfil, 3),
            'patch_level': node.state.patch_level,
            'honeypot':    node.state.honeypot,
        }
    return states


def run_and_capture(scenario_name, red_type, blue_type, max_turns, seed):
    rng = random.Random(seed)
    network, start_node = SCENARIOS[scenario_name]()
    red  = RED_AGENTS[red_type](agent_id='red-agent',   team=Team.RED,  start_node=start_node, rng=rng)
    blue = BLUE_AGENTS[blue_type](agent_id='blue-agent', team=Team.BLUE, rng=rng)

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
                'turn':             r.turn,
                'red_action_type':  r.red_action.action_type.value,
                'red_target':       r.red_action.target_node,
                'red_status':       r.red_outcome.status.value,
                'red_msg':          r.red_outcome.message,
                'red_reward':       round(r.red_outcome.reward, 2),
                'blue_action_type': r.blue_action.action_type.value,
                'blue_target':      r.blue_action.target_node,
                'blue_status':      r.blue_outcome.status.value,
                'blue_msg':         r.blue_outcome.message,
                'blue_reward':      round(r.blue_outcome.reward, 2),
                'red_score':        round(r.red_score, 2),
                'blue_score':       round(r.blue_score, 2),
                'alerts':           r.alerts,
            })
            snapshots.append(capture_node_states(network))

    nodes = []
    for node in network.all_nodes():
        nodes.append({
            'id':              node.id,
            'label':           node.label,
            'type':            node.node_type.value,
            'value':           node.value,
            'services':        [str(s) for s in node.services],
            'vulnerabilities': [{'cve': v.cve_id, 'cvss': v.cvss} for v in node.vulnerabilities],
        })

    edges = []
    for src, dst in network.graph.edges():
        e = network.edge(src, dst)
        edges.append({'source': src, 'target': dst, 'monitored': e.monitored if e else False})

    return {
        'scenario':     network.name,
        'winner':       (engine.winner or Team.BLUE).value,
        'total_turns':  engine.turn,
        'nodes':        nodes,
        'edges':        edges,
        'history':      history,
        'snapshots':    snapshots,
    }


def embed_into_html(game_data, template_path, out_path):
    with open(template_path) as f:
        html = f.read()
    json_str = json.dumps(game_data, separators=(',', ':'))
    html = html.replace('GAME_DATA_PLACEHOLDER', json_str)
    with open(out_path, 'w') as f:
        f.write(html)
    print(f"✓ Replay saved to: {out_path}")
    print(f"  Scenario: {game_data['scenario']}")
    print(f"  Turns: {game_data['total_turns']}  |  Winner: {game_data['winner'].upper()}")
    print(f"  Nodes: {len(game_data['nodes'])}  |  File size: {os.path.getsize(out_path):,} bytes")


def main():
    parser = argparse.ArgumentParser(description='Generate CyberWar battle replay HTML')
    parser.add_argument('--scenario', default='corporate', choices=list(SCENARIOS.keys()))
    parser.add_argument('--red',      default='heuristic', choices=list(RED_AGENTS.keys()))
    parser.add_argument('--blue',     default='heuristic', choices=list(BLUE_AGENTS.keys()))
    parser.add_argument('--turns',    type=int, default=20)
    parser.add_argument('--seed',     type=int, default=99)
    parser.add_argument('--out',      default='battle_replay.html')
    args = parser.parse_args()

    print(f"Running: {args.scenario} | Red={args.red} vs Blue={args.blue} | seed={args.seed}")
    game_data = run_and_capture(args.scenario, args.red, args.blue, args.turns, args.seed)
    embed_into_html(game_data, TEMPLATE_PATH, args.out)


if __name__ == '__main__':
    main()
