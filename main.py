"""
CyberWar Sandbox — Main Entrypoint
====================================
Run a wargame simulation from the command line.

Usage:
    # Claude red vs heuristic blue (requires ANTHROPIC_API_KEY)
    python main.py --red claude --blue heuristic --scenario corporate

    # Claude vs Claude (the main event)
    python main.py --red claude --blue claude --scenario ics --turns 15

    # Heuristic baseline (no API key needed)
    python main.py --red heuristic --blue heuristic --scenario corporate

    # Generate battle replay HTML
    python main.py --red claude --blue heuristic --out replay.html

    python main.py --list-scenarios
"""

import argparse
import os
import random
import sys
import time
import json

sys.path.insert(0, os.path.dirname(__file__))

from env.network import Team
from engine.engine import SimulationEngine, WinCondition, TurnRecord
from agents.agents import (
    RandomRedAgent, HeuristicRedAgent,
    RandomBlueAgent, HeuristicBlueAgent,
)
from scenarios.scenarios import corporate_network, ics_network, cloud_network

# ─── ANSI colours ────────────────────────────────────────────────────────────
RED    = "\033[91m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
AMBER  = "\033[93m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SCENARIOS = {
    "corporate": corporate_network,
    "ics":       ics_network,
    "cloud":     cloud_network,
}


def _try_import_claude():
    try:
        from agents.claude_agent import ClaudeAgent
        return ClaudeAgent
    except ImportError as e:
        print(f"{AMBER}Warning: could not import ClaudeAgent: {e}{RESET}")
        print("Install with: pip install anthropic")
        sys.exit(1)


def build_agents(red_type, blue_type, start_node, rng, args):
    """Construct red and blue agents based on type strings."""
    # RED
    if red_type == "claude":
        ClaudeAgent = _try_import_claude()
        red = ClaudeAgent(
            agent_id   = "red-claude",
            team       = Team.RED,
            start_node = start_node,
            model      = args.model,
            verbose    = args.llm_verbose,
            rng        = rng,
        )
    elif red_type == "heuristic":
        red = HeuristicRedAgent(agent_id="red-heuristic", team=Team.RED,
                                start_node=start_node, rng=rng)
    else:
        red = RandomRedAgent(agent_id="red-random", team=Team.RED,
                             start_node=start_node, rng=rng)

    # BLUE
    if blue_type == "claude":
        ClaudeAgent = _try_import_claude()
        blue = ClaudeAgent(
            agent_id = "blue-claude",
            team     = Team.BLUE,
            model    = args.model,
            verbose  = args.llm_verbose,
            rng      = rng,
        )
    elif blue_type == "heuristic":
        blue = HeuristicBlueAgent(agent_id="blue-heuristic", team=Team.BLUE, rng=rng)
    else:
        blue = RandomBlueAgent(agent_id="blue-random", team=Team.BLUE, rng=rng)

    return red, blue


# ─── Terminal display ─────────────────────────────────────────────────────────

def _action_str(action_type, target, status):
    icons = {
        "exploit": "⚡", "scan": "◎", "lateral_move": "⤳", "exfiltrate": "⬁",
        "privilege_esc": "▲", "persist": "⚓", "ddos": "💥",
        "patch": "✚", "isolate": "⊘", "restore": "↺", "monitor": "◈",
        "hunt": "⚑", "deploy_honeypot": "⊛", "harden": "⬡",
        "block_edge": "╳", "pass": "—",
    }
    icon = icons.get(action_type, "?")
    target_str   = f" → {target}" if target else ""
    status_color = GREEN if status == "success" else (DIM if status == "failure" else AMBER)
    status_char  = "✓" if status == "success" else ("✗" if status == "failure" else "⚠")
    return f"{icon} {action_type.upper().replace('_',' ')}{target_str} {status_color}{status_char}{RESET}"


def print_turn(record: TurnRecord):
    r = record
    print(f"\n{DIM}{'─'*64}{RESET}")
    print(f"{BOLD}Turn {r.turn:02d}{RESET}  "
          f"Red={RED}{r.red_score:.1f}{RESET}  Blue={BLUE}{r.blue_score:.1f}{RESET}")
    print(f"  {RED}🔴{RESET} {_action_str(r.red_action.action_type.value,  r.red_action.target_node,  r.red_outcome.status.value)}")
    print(f"  {BLUE}🔵{RESET} {_action_str(r.blue_action.action_type.value, r.blue_action.target_node, r.blue_outcome.status.value)}")
    for alert in r.alerts:
        print(f"  {AMBER}⚠  {alert}{RESET}")


def print_header(scenario_name, network, red_type, blue_type, seed):
    print(f"\n{BOLD}{'═'*64}{RESET}")
    print(f"  {BOLD}{RED}CYBER{RESET}{BOLD}{BLUE}WAR{RESET} SANDBOX")
    print(f"  Scenario : {BOLD}{scenario_name.upper()}{RESET}  ({network})")
    print(f"  Red      : {RED}{red_type}{RESET}")
    print(f"  Blue     : {BLUE}{blue_type}{RESET}")
    print(f"  Seed     : {seed}")
    print(f"{BOLD}{'═'*64}{RESET}\n")


def print_final(engine, red_type, blue_type):
    print(f"\n{BOLD}{'═'*64}{RESET}")
    winner = engine.winner or Team.BLUE
    color  = RED if winner == Team.RED else BLUE
    print(f"  {BOLD}{color}🏆 {winner.value.upper()} WINS{RESET}  at turn {engine.turn}")
    print(f"{BOLD}{'═'*64}{RESET}")
    print(engine.final_report())
    for agent in [engine.red_agent, engine.blue_agent]:
        if hasattr(agent, "stats_summary"):
            print(f"\n{DIM}{agent.stats_summary()}{RESET}")


# ─── Engine with outcome feedback ─────────────────────────────────────────────

class FeedbackEngine(SimulationEngine):
    """Feeds turn outcomes back to ClaudeAgents so they maintain context."""
    def step(self):
        record = super().step()
        if record is None:
            return None
        for agent, outcome in [(self.red_agent, record.red_outcome),
                                (self.blue_agent, record.blue_outcome)]:
            if hasattr(agent, "record_outcome"):
                agent.record_outcome(f"[{outcome.status.value.upper()}] {outcome.message}")
        return record


# ─── Replay HTML generator ────────────────────────────────────────────────────

def generate_replay_html(engine, network, args):
    template_path = os.path.join(os.path.dirname(__file__), "cyberwar_ui_template.html")
    if not os.path.exists(template_path):
        print(f"{AMBER}Warning: template not found at {template_path}{RESET}")
        return

    history = []
    for rec in engine.history:
        history.append({
            "turn": rec.turn,
            "red_action_type":  rec.red_action.action_type.value,
            "red_target":       rec.red_action.target_node,
            "red_status":       rec.red_outcome.status.value,
            "red_msg":          rec.red_outcome.message,
            "red_reward":       round(rec.red_outcome.reward, 2),
            "blue_action_type": rec.blue_action.action_type.value,
            "blue_target":      rec.blue_action.target_node,
            "blue_status":      rec.blue_outcome.status.value,
            "blue_msg":         rec.blue_outcome.message,
            "blue_reward":      round(rec.blue_outcome.reward, 2),
            "red_score":        round(rec.red_score, 2),
            "blue_score":       round(rec.blue_score, 2),
            "alerts":           rec.alerts,
        })

    # Final state snapshot (repeated for each turn — see generate_ui.py for per-turn capture)
    snap = {n.id: {
        "owner": n.state.owner.value, "compromised": n.state.compromised,
        "isolated": n.state.isolated, "alert_level": n.state.alert_level,
        "data_exfil": round(n.state.data_exfil, 3),
        "patch_level": n.state.patch_level, "honeypot": n.state.honeypot,
    } for n in network.all_nodes()}
    snapshots = [snap] * (len(history) + 1)

    nodes = [{"id": n.id, "label": n.label, "type": n.node_type.value, "value": n.value,
               "services": [str(s) for s in n.services],
               "vulnerabilities": [{"cve": v.cve_id, "cvss": v.cvss} for v in n.vulnerabilities]}
             for n in network.all_nodes()]
    edges = [{"source": src, "target": dst,
               "monitored": (network.edge(src, dst).monitored if network.edge(src, dst) else False)}
             for src, dst in network.graph.edges()]

    game_data = {
        "scenario": network.name, "winner": (engine.winner or Team.BLUE).value,
        "total_turns": engine.turn, "nodes": nodes, "edges": edges,
        "history": history, "snapshots": snapshots,
    }

    with open(template_path) as f:
        html = f.read()
    html = html.replace("GAME_DATA_PLACEHOLDER", json.dumps(game_data, separators=(",", ":")))
    with open(args.out, "w") as f:
        f.write(html)
    print(f"\n{GREEN}✓ Replay saved: {args.out}  ({os.path.getsize(args.out):,} bytes){RESET}")


# ─── Main game runner ─────────────────────────────────────────────────────────

def run_game(args):
    rng = random.Random(args.seed)
    network, start_node = SCENARIOS[args.scenario]()
    red, blue = build_agents(args.red, args.blue, start_node, rng, args)

    engine = FeedbackEngine(
        network=network, red_agent=red, blue_agent=blue,
        win_condition=WinCondition(max_turns=args.turns),
        mode="sequential", rng=rng, verbose=False,
    )

    print_header(args.scenario, network, args.red, args.blue, args.seed)

    while engine.winner is None and engine.turn < args.turns:
        record = engine.step()
        if record and not args.quiet:
            print_turn(record)
        if (args.red == "claude" or args.blue == "claude") and args.delay > 0:
            time.sleep(args.delay)

    print_final(engine, args.red, args.blue)

    if args.out:
        generate_replay_html(engine, network, args)

    return engine


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberWar Agentic Sandbox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --red claude --blue heuristic
  python main.py --red claude --blue claude --scenario ics --turns 15 --llm-verbose
  python main.py --red heuristic --blue heuristic --quiet
  python main.py --red claude --blue heuristic --out battle.html
  python main.py --red claude --blue claude --model claude-opus-4-6 --turns 20
        """,
    )
    parser.add_argument("--scenario",    default="corporate", choices=list(SCENARIOS.keys()))
    parser.add_argument("--red",         default="heuristic", choices=["heuristic", "random", "claude"])
    parser.add_argument("--blue",        default="heuristic", choices=["heuristic", "random", "claude"])
    parser.add_argument("--turns",       type=int,   default=20)
    parser.add_argument("--seed",        type=int,   default=99)
    parser.add_argument("--model",       default="claude-haiku-4-5-20251001",
                        help="Claude model (default: haiku — fast/cheap for games)")
    parser.add_argument("--quiet",       action="store_true", help="Suppress turn-by-turn output")
    parser.add_argument("--llm-verbose", action="store_true", help="Print Claude's reasoning each turn",
                        dest="llm_verbose")
    parser.add_argument("--delay",       type=float, default=0.5,
                        help="Seconds between turns when using Claude agents")
    parser.add_argument("--out",         default=None, help="Save battle replay HTML to this path")
    parser.add_argument("--list-scenarios", action="store_true")
    args = parser.parse_args()

    if args.list_scenarios:
        for name, fn in SCENARIOS.items():
            net, _ = fn()
            print(f"  {name:<12} — {net}")
        return

    if args.red == "claude" or args.blue == "claude":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print(f"\n{AMBER}Error: ANTHROPIC_API_KEY not set.{RESET}")
            print("  export ANTHROPIC_API_KEY=sk-ant-...")
            sys.exit(1)

    run_game(args)


if __name__ == "__main__":
    main()
