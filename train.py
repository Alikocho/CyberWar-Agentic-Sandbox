"""
train.py
========
Reinforcement Learning training loop for CyberWar.

Trains PPO agents via self-play:
  - RLRedAgent  trains against a frozen HeuristicBlueAgent
  - RLBlueAgent trains against a frozen HeuristicRedAgent
  - (Optional) full self-play: both RL agents face each other

Usage
-----
    # Train red agent only (fast, ~5 min for 500 episodes)
    python train.py --team red --episodes 500

    # Train both teams
    python train.py --team both --episodes 1000

    # Train with curriculum (starts vs random, then escalates to heuristic)
    python train.py --team red --curriculum --episodes 800

    # Resume from checkpoint
    python train.py --team red --load checkpoints/red_ep400.npz

    # Generate battle replay HTML from trained agent
    python train.py --team red --load checkpoints/red_ep500.npz --eval-only --out trained_vs_heuristic.html

    # Full self-play
    python train.py --team both --self-play --episodes 1000
"""

import argparse
import json
import os
import random
import sys
import time
from collections import deque
from dataclasses import dataclass, asdict
from typing import Optional

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

from env.network import Team
from engine.engine import SimulationEngine, WinCondition, TurnRecord
from agents.agents import (
    HeuristicRedAgent, HeuristicBlueAgent,
    RandomRedAgent, RandomBlueAgent,
)
from scenarios.scenarios import corporate_network, ics_network, cloud_network
from rl.ppo_agent import (
    PPOPolicy, PPOConfig, RLRedAgent, RLBlueAgent,
    ALL_KNOWN_NODES, STATE_DIM, RED_ACTION_TYPES, BLUE_ACTION_TYPES,
)

# ──────────────────────────────────────────────────────────────────────────────
# ANSI
# ──────────────────────────────────────────────────────────────────────────────
RED   = "\033[91m"; BLUE = "\033[94m"; GREEN = "\033[92m"
AMBER = "\033[93m"; DIM  = "\033[2m";  BOLD  = "\033[1m"; RESET = "\033[0m"

SCENARIOS = {
    "corporate": corporate_network,
    "ics":       ics_network,
    "cloud":     cloud_network,
}


# ──────────────────────────────────────────────────────────────────────────────
# Reward shaping
# ──────────────────────────────────────────────────────────────────────────────

def red_shaped_reward(record: TurnRecord, done: bool, winner: Optional[Team]) -> float:
    """
    Dense reward signal for red agent.
    Raw engine reward is too sparse — shape it to guide learning.
    """
    r = record.red_outcome.reward    # base reward from engine

    # Terminal bonuses/penalties
    if done:
        if winner == Team.RED:
            r += 10.0   # win bonus
        else:
            r -= 5.0    # loss penalty

    # Shaping: penalise detected actions
    if record.red_outcome.status.value == "detected":
        r -= 0.5

    # Shaping: reward progress (score increase)
    # (baseline engine reward already includes this but reinforce it)
    r += 0.1 * record.red_outcome.reward

    return float(np.clip(r, -20.0, 20.0))


def blue_shaped_reward(record: TurnRecord, done: bool, winner: Optional[Team]) -> float:
    """Dense reward signal for blue agent."""
    r = record.blue_outcome.reward

    if done:
        if winner == Team.BLUE:
            r += 10.0
        else:
            r -= 5.0

    # Shaping: reward catching red (high alerts → detection is good)
    if record.blue_outcome.status.value == "success" and \
       record.blue_action.action_type.value in ("hunt", "restore", "isolate"):
        r += 0.5

    return float(np.clip(r, -20.0, 20.0))


# ──────────────────────────────────────────────────────────────────────────────
# Engine wrapper that feeds shaped rewards to RL agents
# ──────────────────────────────────────────────────────────────────────────────

class TrainingEngine(SimulationEngine):
    """Wraps SimulationEngine to call record_step() on RL agents after each turn."""

    def __init__(self, rl_team: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rl_team = rl_team   # "red", "blue", or "both"

    def step(self):
        record = super().step()
        if record is None:
            return None

        done   = self.winner is not None
        winner = self.winner

        if self.rl_team in ("red", "both"):
            if hasattr(self.red_agent, "record_step"):
                rr = red_shaped_reward(record, done, winner)
                self.red_agent.record_step(rr, done)

        if self.rl_team in ("blue", "both"):
            if hasattr(self.blue_agent, "record_step"):
                br = blue_shaped_reward(record, done, winner)
                self.blue_agent.record_step(br, done)

        return record


# ──────────────────────────────────────────────────────────────────────────────
# Training metrics tracker
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class EpisodeResult:
    episode:      int
    scenario:     str
    winner:       str
    turns:        int
    red_score:    float
    blue_score:   float
    red_reward:   float
    blue_reward:  float
    red_compromised: int
    total_nodes:  int


class MetricsTracker:
    def __init__(self, window: int = 50):
        self.window       = window
        self.history:     list[EpisodeResult] = []
        self.win_rates    = deque(maxlen=window)
        self.red_scores   = deque(maxlen=window)
        self.blue_scores  = deque(maxlen=window)
        self.red_rewards  = deque(maxlen=window)
        self.blue_rewards = deque(maxlen=window)
        self.turns_hist   = deque(maxlen=window)

    def record(self, result: EpisodeResult):
        self.history.append(result)
        self.win_rates.append(1.0 if result.winner == "red" else 0.0)
        self.red_scores.append(result.red_score)
        self.blue_scores.append(result.blue_score)
        self.red_rewards.append(result.red_reward)
        self.blue_rewards.append(result.blue_reward)
        self.turns_hist.append(result.turns)

    def summary(self) -> dict:
        if not self.win_rates:
            return {}
        return {
            "red_win_rate":  round(float(np.mean(self.win_rates)),  3),
            "avg_red_score": round(float(np.mean(self.red_scores)), 2),
            "avg_turns":     round(float(np.mean(self.turns_hist)), 1),
            "avg_red_rew":   round(float(np.mean(self.red_rewards)),2),
        }

    def save_jsonl(self, path: str):
        with open(path, "w") as f:
            for r in self.history:
                f.write(json.dumps(asdict(r)) + "\n")


# ──────────────────────────────────────────────────────────────────────────────
# Opponent curricula
# ──────────────────────────────────────────────────────────────────────────────

def make_opponent(team: Team, difficulty: str, start_node: str, rng) -> object:
    """Build a frozen opponent at the given difficulty level."""
    if team == Team.RED:
        if difficulty == "random":
            return RandomRedAgent(agent_id="red-opp", team=Team.RED,
                                  start_node=start_node, rng=rng)
        return HeuristicRedAgent(agent_id="red-opp", team=Team.RED,
                                 start_node=start_node, rng=rng)
    else:
        if difficulty == "random":
            return RandomBlueAgent(agent_id="blue-opp", team=Team.BLUE, rng=rng)
        return HeuristicBlueAgent(agent_id="blue-opp", team=Team.BLUE, rng=rng)


def curriculum_difficulty(episode: int, total: int) -> str:
    """Ramp opponent difficulty over training."""
    frac = episode / max(total, 1)
    if frac < 0.25:
        return "random"
    return "heuristic"


# ──────────────────────────────────────────────────────────────────────────────
# Single episode runner
# ──────────────────────────────────────────────────────────────────────────────

def run_episode(
    rl_team:     str,
    red_agent,
    blue_agent,
    scenario_fn,
    max_turns:   int = 20,
    seed:        Optional[int] = None,
) -> EpisodeResult:
    rng  = random.Random(seed)
    network, start_node = scenario_fn()

    # Reset RL agents for new episode
    for agent in [red_agent, blue_agent]:
        if hasattr(agent, "reset_episode"):
            agent.reset_episode()
        if hasattr(agent, "start_node"):
            agent.start_node = start_node

    engine = TrainingEngine(
        rl_team      = rl_team,
        network      = network,
        red_agent    = red_agent,
        blue_agent   = blue_agent,
        win_condition= WinCondition(max_turns=max_turns),
        mode         = "sequential",
        rng          = rng,
        verbose      = False,
    )

    while engine.winner is None and engine.turn < max_turns:
        engine.step()

    winner = (engine.winner or Team.BLUE).value
    nodes  = network.all_nodes()
    compromised = sum(1 for n in nodes if n.state.compromised)

    return EpisodeResult(
        episode      = 0,   # filled in by caller
        scenario     = network.name,
        winner       = winner,
        turns        = engine.turn,
        red_score    = round(network.red_score(), 2),
        blue_score   = round(network.blue_score(), 2),
        red_reward   = getattr(red_agent,  "episode_reward", 0.0),
        blue_reward  = getattr(blue_agent, "episode_reward", 0.0),
        red_compromised = compromised,
        total_nodes  = len(list(nodes)),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Evaluation (no training updates, deterministic-ish)
# ──────────────────────────────────────────────────────────────────────────────

def evaluate(
    rl_team: str,
    red_agent,
    blue_agent,
    scenario_fn,
    n_games: int = 20,
    max_turns: int = 20,
) -> dict:
    wins  = 0
    red_scores = []
    turns_list = []

    # Disable training during eval
    for agent in [red_agent, blue_agent]:
        if hasattr(agent, "training"):
            agent.training = False

    for i in range(n_games):
        result = run_episode(rl_team, red_agent, blue_agent,
                             scenario_fn, max_turns=max_turns,
                             seed=1000 + i)
        if result.winner == "red":
            wins += 1
        red_scores.append(result.red_score)
        turns_list.append(result.turns)

    for agent in [red_agent, blue_agent]:
        if hasattr(agent, "training"):
            agent.training = True

    return {
        "win_rate":   round(wins / n_games, 3),
        "avg_score":  round(float(np.mean(red_scores)), 2),
        "avg_turns":  round(float(np.mean(turns_list)), 1),
        "n_games":    n_games,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Replay HTML generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_replay(red_agent, blue_agent, scenario_fn, out_path: str,
                    max_turns: int = 20, seed: int = 42):
    """Run one game and save a visual replay HTML."""
    import json as _json

    template_path = os.path.join(os.path.dirname(__file__), "cyberwar_ui_template.html")
    if not os.path.exists(template_path):
        print(f"{AMBER}Template not found: {template_path}{RESET}")
        return

    rng = random.Random(seed)
    network, start_node = scenario_fn()

    for agent in [red_agent, blue_agent]:
        if hasattr(agent, "reset_episode"):
            agent.reset_episode()
        if hasattr(agent, "start_node"):
            agent.start_node = start_node
        if hasattr(agent, "training"):
            agent.training = False

    def snap(net):
        return {n.id: {
            "owner": n.state.owner.value, "compromised": n.state.compromised,
            "isolated": n.state.isolated, "alert_level": n.state.alert_level,
            "data_exfil": round(n.state.data_exfil, 3),
            "patch_level": n.state.patch_level, "honeypot": n.state.honeypot,
        } for n in net.all_nodes()}

    engine = TrainingEngine(
        rl_team="both", network=network,
        red_agent=red_agent, blue_agent=blue_agent,
        win_condition=WinCondition(max_turns=max_turns),
        mode="sequential", rng=rng, verbose=False,
    )

    snapshots = [snap(network)]
    history   = []
    while engine.winner is None and engine.turn < max_turns:
        rec = engine.step()
        if rec:
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
            snapshots.append(snap(network))

    nodes = [{"id": n.id, "label": n.label, "type": n.node_type.value, "value": n.value,
               "services": [str(s) for s in n.services],
               "vulnerabilities": [{"cve": v.cve_id, "cvss": v.cvss} for v in n.vulnerabilities]}
             for n in network.all_nodes()]
    edges = [{"source": s, "target": d,
               "monitored": (network.edge(s, d).monitored if network.edge(s, d) else False)}
             for s, d in network.graph.edges()]

    game_data = {
        "scenario": network.name,
        "winner":   (engine.winner or Team.BLUE).value,
        "total_turns": engine.turn,
        "nodes": nodes, "edges": edges,
        "history": history, "snapshots": snapshots,
    }

    with open(template_path) as f:
        html = f.read()
    html = html.replace("GAME_DATA_PLACEHOLDER",
                        _json.dumps(game_data, separators=(",", ":")))
    with open(out_path, "w") as f:
        f.write(html)
    print(f"{GREEN}✓ Replay saved: {out_path}  "
          f"({os.path.getsize(out_path):,} bytes){RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# Progress bar
# ──────────────────────────────────────────────────────────────────────────────

def progress_bar(ep: int, total: int, width: int = 30) -> str:
    filled = int(width * ep / max(total, 1))
    bar    = "█" * filled + "░" * (width - filled)
    pct    = 100.0 * ep / max(total, 1)
    return f"[{bar}] {pct:5.1f}% ({ep}/{total})"


# ──────────────────────────────────────────────────────────────────────────────
# Main training loop
# ──────────────────────────────────────────────────────────────────────────────

def train(args):
    os.makedirs(args.checkpoint_dir, exist_ok=True)

    cfg = PPOConfig(
        hidden_dim   = args.hidden_dim,
        lr           = args.lr,
        gamma        = args.gamma,
        lam          = args.lam,
        clip_eps     = args.clip_eps,
        entropy_coef = args.entropy_coef,
        n_epochs     = args.ppo_epochs,
        batch_size   = args.batch_size,
    )

    # Build scenario list (rotate through all scenarios for robustness)
    scenario_fns = [SCENARIOS[s] for s in args.scenarios]

    # Build node order from the union of all scenario nodes
    node_order = list(ALL_KNOWN_NODES)

    red_action_dim  = len(RED_ACTION_TYPES)  * len(node_order)
    blue_action_dim = len(BLUE_ACTION_TYPES) * len(node_order)

    print(f"\n{BOLD}{'═'*64}{RESET}")
    print(f"  {BOLD}{RED}CYBER{RESET}{BOLD}{BLUE}WAR{RESET} RL TRAINING")
    print(f"  Team      : {args.team}")
    print(f"  Scenarios : {args.scenarios}")
    print(f"  Episodes  : {args.episodes}")
    print(f"  State dim : {STATE_DIM}")
    print(f"  Red acts  : {red_action_dim}  Blue acts: {blue_action_dim}")
    print(f"  Algorithm : PPO  lr={cfg.lr}  γ={cfg.gamma}  λ={cfg.lam}")
    print(f"  Curriculum: {'yes' if args.curriculum else 'no'}")
    print(f"{BOLD}{'═'*64}{RESET}\n")

    # ── Instantiate policies ──────────────────────────────────────────────────
    red_policy  = PPOPolicy(STATE_DIM, red_action_dim,  cfg, seed=args.seed)
    blue_policy = PPOPolicy(STATE_DIM, blue_action_dim, cfg, seed=args.seed + 1)

    if args.load_red:
        red_policy.load(args.load_red)
        print(f"{GREEN}Loaded red checkpoint: {args.load_red}{RESET}")
    if args.load_blue:
        blue_policy.load(args.load_blue)
        print(f"{GREEN}Loaded blue checkpoint: {args.load_blue}{RESET}")

    # Metrics
    metrics      = MetricsTracker(window=args.log_window)
    ppo_metrics  = {"policy_loss": deque(maxlen=50), "value_loss": deque(maxlen=50),
                    "entropy": deque(maxlen=50), "kl": deque(maxlen=50)}
    start_time   = time.time()
    best_win_rate= 0.0

    # ── Episode loop ──────────────────────────────────────────────────────────
    for ep in range(1, args.episodes + 1):
        seed         = args.seed + ep
        scenario_fn  = scenario_fns[(ep - 1) % len(scenario_fns)]
        difficulty   = curriculum_difficulty(ep, args.episodes) \
                       if args.curriculum else "heuristic"

        # Fresh scenario to get start_node
        _net, start_node = scenario_fn()

        # Build agents for this episode
        if args.team == "red":
            rl_red   = RLRedAgent(agent_id="red-rl", team=Team.RED,
                                  start_node=start_node, policy=red_policy,
                                  node_order=node_order, training=True)
            blue_opp = make_opponent(Team.BLUE, difficulty, start_node, random.Random(seed))
            result = run_episode("red", rl_red, blue_opp, scenario_fn,
                                 max_turns=args.max_turns, seed=seed)
            ppo_m = rl_red.update()
            result.episode = ep
            metrics.record(result)

        elif args.team == "blue":
            red_opp  = make_opponent(Team.RED, difficulty, start_node, random.Random(seed))
            rl_blue  = RLBlueAgent(agent_id="blue-rl", team=Team.BLUE,
                                   policy=blue_policy, node_order=node_order, training=True)
            result = run_episode("blue", red_opp, rl_blue, scenario_fn,
                                 max_turns=args.max_turns, seed=seed)
            ppo_m = rl_blue.update()
            result.episode = ep
            metrics.record(result)

        else:  # both — self-play
            rl_red  = RLRedAgent(agent_id="red-rl",  team=Team.RED,
                                 start_node=start_node, policy=red_policy,
                                 node_order=node_order, training=True)
            rl_blue = RLBlueAgent(agent_id="blue-rl", team=Team.BLUE,
                                  policy=blue_policy, node_order=node_order, training=True)
            result = run_episode("both", rl_red, rl_blue, scenario_fn,
                                 max_turns=args.max_turns, seed=seed)
            ppo_mr = rl_red.update()
            ppo_mb = rl_blue.update()
            ppo_m  = ppo_mr  # log red's metrics
            result.episode = ep
            metrics.record(result)

        # Accumulate PPO metrics
        for k, v in ppo_m.items():
            if k in ppo_metrics:
                ppo_metrics[k].append(v)

        # ── Logging ──────────────────────────────────────────────────────────
        if ep % args.log_every == 0:
            elapsed = time.time() - start_time
            s       = metrics.summary()
            wr      = s.get("red_win_rate", 0)
            color   = GREEN if wr > 0.5 else (AMBER if wr > 0.3 else RED)

            ppo_str = ""
            if ppo_metrics["policy_loss"]:
                ppo_str = (f"  ploss={np.mean(ppo_metrics['policy_loss']):.3f} "
                           f"vloss={np.mean(ppo_metrics['value_loss']):.3f} "
                           f"ent={np.mean(ppo_metrics['entropy']):.3f} "
                           f"kl={np.mean(ppo_metrics['kl']):.4f}")

            print(f"\r{progress_bar(ep, args.episodes)}"
                  f"  win={color}{wr:.1%}{RESET}"
                  f"  score={s.get('avg_red_score', 0):.1f}"
                  f"  turns={s.get('avg_turns', 0):.0f}"
                  f"  {DIM}{elapsed:.0f}s{RESET}"
                  f"{ppo_str}")

        # ── Evaluation ───────────────────────────────────────────────────────
        if ep % args.eval_every == 0:
            print(f"\n{DIM}  Evaluating {args.eval_games} games...{RESET}", end="", flush=True)

            eval_net, eval_start = scenario_fn()

            if args.team in ("red", "both"):
                eval_red = RLRedAgent(agent_id="red-eval", team=Team.RED,
                                      start_node=eval_start, policy=red_policy,
                                      node_order=node_order, training=False)
                eval_blue = HeuristicBlueAgent(agent_id="blue-eval", team=Team.BLUE)
                ev = evaluate("red", eval_red, eval_blue, scenario_fn,
                              n_games=args.eval_games, max_turns=args.max_turns)
            else:
                eval_red  = HeuristicRedAgent(agent_id="red-eval", team=Team.RED,
                                               start_node=eval_start)
                eval_blue = RLBlueAgent(agent_id="blue-eval", team=Team.BLUE,
                                        policy=blue_policy, node_order=node_order, training=False)
                ev = evaluate("blue", eval_red, eval_blue, scenario_fn,
                              n_games=args.eval_games, max_turns=args.max_turns)

            wr_color = GREEN if ev["win_rate"] > 0.5 else (AMBER if ev["win_rate"] > 0.3 else RED)
            print(f"  EVAL ep={ep}:"
                  f"  win={wr_color}{ev['win_rate']:.1%}{RESET}"
                  f"  score={ev['avg_score']:.1f}"
                  f"  turns={ev['avg_turns']:.0f}")

            # Save best checkpoint
            if ev["win_rate"] > best_win_rate:
                best_win_rate = ev["win_rate"]
                if args.team in ("red", "both"):
                    p = os.path.join(args.checkpoint_dir, "red_best.npz")
                    red_policy.save(p)
                    print(f"  {GREEN}★ New best red checkpoint (win={best_win_rate:.1%}){RESET}")
                if args.team in ("blue", "both"):
                    p = os.path.join(args.checkpoint_dir, "blue_best.npz")
                    blue_policy.save(p)
                    print(f"  {GREEN}★ New best blue checkpoint (win={best_win_rate:.1%}){RESET}")

        # ── Checkpointing ────────────────────────────────────────────────────
        if ep % args.save_every == 0:
            if args.team in ("red", "both"):
                p = os.path.join(args.checkpoint_dir, f"red_ep{ep}.npz")
                red_policy.save(p)
            if args.team in ("blue", "both"):
                p = os.path.join(args.checkpoint_dir, f"blue_ep{ep}.npz")
                blue_policy.save(p)
            print(f"  {DIM}Checkpointed ep={ep}{RESET}")

    # ── Final save & report ───────────────────────────────────────────────────
    if args.team in ("red", "both"):
        red_policy.save(os.path.join(args.checkpoint_dir, "red_final.npz"))
    if args.team in ("blue", "both"):
        blue_policy.save(os.path.join(args.checkpoint_dir, "blue_final.npz"))

    metrics.save_jsonl(os.path.join(args.checkpoint_dir, "training_log.jsonl"))

    elapsed = time.time() - start_time
    s = metrics.summary()
    print(f"\n{BOLD}{'═'*64}{RESET}")
    print(f"  Training complete  ({elapsed:.1f}s, {ep} episodes)")
    print(f"  Final window stats: {s}")
    print(f"  Checkpoints in: {args.checkpoint_dir}/")
    print(f"{BOLD}{'═'*64}{RESET}\n")

    # ── Optional replay ───────────────────────────────────────────────────────
    if args.out:
        scenario_fn = scenario_fns[0]
        _n, sn = scenario_fn()
        if args.team in ("red", "both"):
            r_agent = RLRedAgent(agent_id="red-rl", team=Team.RED, start_node=sn,
                                 policy=red_policy, node_order=node_order, training=False)
            b_agent = HeuristicBlueAgent(agent_id="blue-heur", team=Team.BLUE)
        else:
            r_agent = HeuristicRedAgent(agent_id="red-heur", team=Team.RED, start_node=sn)
            b_agent = RLBlueAgent(agent_id="blue-rl", team=Team.BLUE,
                                  policy=blue_policy, node_order=node_order, training=False)
        generate_replay(r_agent, b_agent, scenario_fn, args.out, max_turns=args.max_turns)

    return red_policy, blue_policy


# ──────────────────────────────────────────────────────────────────────────────
# Eval-only mode (load checkpoint, run games, optionally save replay)
# ──────────────────────────────────────────────────────────────────────────────

def eval_only(args):
    scenario_fn = SCENARIOS[args.scenarios[0]]
    _n, start_node = scenario_fn()

    node_order = list(ALL_KNOWN_NODES)
    cfg = PPOConfig()

    red_action_dim  = len(RED_ACTION_TYPES)  * len(node_order)
    blue_action_dim = len(BLUE_ACTION_TYPES) * len(node_order)

    if args.team in ("red", "both"):
        red_policy = PPOPolicy(STATE_DIM, red_action_dim, cfg, seed=args.seed)
        if args.load_red:
            red_policy.load(args.load_red)
            print(f"{GREEN}Loaded red: {args.load_red}{RESET}")
        r_agent = RLRedAgent(agent_id="red-rl", team=Team.RED, start_node=start_node,
                             policy=red_policy, node_order=node_order, training=False)
        b_agent = HeuristicBlueAgent(agent_id="blue-heur", team=Team.BLUE)
        rl_team = "red"
    else:
        blue_policy = PPOPolicy(STATE_DIM, blue_action_dim, cfg, seed=args.seed)
        if args.load_blue:
            blue_policy.load(args.load_blue)
            print(f"{GREEN}Loaded blue: {args.load_blue}{RESET}")
        r_agent = HeuristicRedAgent(agent_id="red-heur", team=Team.RED, start_node=start_node)
        b_agent = RLBlueAgent(agent_id="blue-rl", team=Team.BLUE,
                              policy=blue_policy, node_order=node_order, training=False)
        rl_team = "blue"

    ev = evaluate(rl_team, r_agent, b_agent, scenario_fn,
                  n_games=args.eval_games, max_turns=args.max_turns)
    print(f"\nEval results over {ev['n_games']} games:")
    print(f"  Win rate   : {ev['win_rate']:.1%}")
    print(f"  Avg score  : {ev['avg_score']:.1f}")
    print(f"  Avg turns  : {ev['avg_turns']:.1f}")

    if args.out:
        _n2, sn2 = scenario_fn()
        if hasattr(r_agent, "start_node"):
            r_agent.start_node = sn2
        generate_replay(r_agent, b_agent, scenario_fn, args.out, max_turns=args.max_turns)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="CyberWar PPO Training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train red agent (fast, ~5 min)
  python train.py --team red --episodes 500

  # Train red with curriculum (starts easy, gets harder)
  python train.py --team red --episodes 800 --curriculum

  # Train both via self-play
  python train.py --team both --episodes 1000

  # Resume from checkpoint
  python train.py --team red --load-red checkpoints/red_ep400.npz --episodes 200

  # Eval + save replay HTML
  python train.py --team red --load-red checkpoints/red_best.npz --eval-only --out rl_replay.html
        """,
    )
    p.add_argument("--team",       default="red", choices=["red", "blue", "both"])
    p.add_argument("--episodes",   type=int,   default=500)
    p.add_argument("--scenarios",  nargs="+",  default=["corporate"],
                   choices=list(SCENARIOS.keys()))
    p.add_argument("--max-turns",  type=int,   default=20,   dest="max_turns")
    p.add_argument("--seed",       type=int,   default=42)

    # PPO hyperparams
    p.add_argument("--lr",           type=float, default=3e-4)
    p.add_argument("--gamma",        type=float, default=0.99)
    p.add_argument("--lam",          type=float, default=0.95)
    p.add_argument("--clip-eps",     type=float, default=0.2,  dest="clip_eps")
    p.add_argument("--entropy-coef", type=float, default=0.01, dest="entropy_coef")
    p.add_argument("--ppo-epochs",   type=int,   default=4,    dest="ppo_epochs")
    p.add_argument("--batch-size",   type=int,   default=64,   dest="batch_size")
    p.add_argument("--hidden-dim",   type=int,   default=128,  dest="hidden_dim")

    # Curriculum / self-play
    p.add_argument("--curriculum",   action="store_true")
    p.add_argument("--self-play",    action="store_true", dest="self_play")

    # Checkpointing
    p.add_argument("--checkpoint-dir", default="checkpoints",  dest="checkpoint_dir")
    p.add_argument("--load-red",       default=None,           dest="load_red")
    p.add_argument("--load-blue",      default=None,           dest="load_blue")
    p.add_argument("--save-every",     type=int, default=100,  dest="save_every")

    # Logging
    p.add_argument("--log-every",   type=int, default=10,  dest="log_every")
    p.add_argument("--log-window",  type=int, default=50,  dest="log_window")
    p.add_argument("--eval-every",  type=int, default=100, dest="eval_every")
    p.add_argument("--eval-games",  type=int, default=20,  dest="eval_games")

    # Output
    p.add_argument("--out",         default=None, help="Save replay HTML after training")
    p.add_argument("--eval-only",   action="store_true", dest="eval_only")

    args = p.parse_args()

    if args.eval_only:
        eval_only(args)
    else:
        train(args)


if __name__ == "__main__":
    main()
