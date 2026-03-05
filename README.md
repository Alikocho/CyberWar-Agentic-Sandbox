# CyberWar Agentic Sandbox

A turn-based, multi-agent cyber wargaming simulation. Red team (attacker) vs Blue team (defender) compete over a graph-based network with partial observability, probabilistic action resolution, and pluggable agent types — including human players, AI heuristics, and Claude LLM agents.

Available as a **desktop app** (no install required) or runnable from source.

---

## Download & Run (Desktop App)

Go to the [Releases page](../../releases) and download the latest version for your platform:

| Platform | File | Requirements |
|----------|------|-------------|
| macOS | `CyberWarSandbox_Mac.zip` | macOS 11+ |
| Windows | `CyberWarSandbox_Windows.zip` | Windows 10+ |

**Mac:** Unzip → right-click `CyberWarSandbox.app` → Open (required first time to bypass Gatekeeper). Or go to **System Settings → Privacy & Security → Open Anyway** after attempting to launch.

**Windows:** Unzip → run `CyberWarSandbox.exe`. The app opens your browser automatically.

---

## What's New in v2.0.0

- **Human player mode** — play as Red team against AI defenders
- **Live game UI** — interactive browser-based interface for human turns
- **Desktop app** — runs as a Mac .app or Windows .exe, no Python required
- **Battle replay** — watch AI vs AI games as animated network graph replays
- **Fog of war** — Red only sees nodes it has discovered; Blue sees everything
- **Custom app icon** — shield with circuit/network pattern

---

## Running from Source

```bash
git clone https://github.com/Alikocho/CyberWar-Agentic-Sandbox.git
cd CyberWar-Agentic-Sandbox
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000` in your browser.

### CLI mode (no UI)

```bash
# Heuristic Red vs Heuristic Blue, corporate network, 20 turns
python main.py

# ICS scenario, Red wins against random blue
python main.py --scenario ics --red heuristic --blue random --turns 15

# Claude LLM red team vs heuristic defender
python main.py --red claude --blue heuristic

# Claude vs Claude
python main.py --red claude --blue claude --scenario ics --turns 15

# Generate a battle replay HTML
python main.py --red claude --blue heuristic --out battle.html
```

---

## Architecture

```
CyberWar-Agentic-Sandbox/
├── app.py                  # Flask server — game sessions, API endpoints
├── launcher.py             # Mac desktop launcher (Tkinter window + Flask)
├── launcher_win.py         # Windows desktop launcher
├── main.py                 # CLI entrypoint
├── templates/
│   └── index.html          # Full game UI (scenario select, replay, live game)
├── agents/
│   ├── agents.py           # BaseAgent, RandomRed/Blue, HeuristicRed/Blue, LLMAgent
│   ├── claude_agent.py     # Claude API agent with tool use
│   └── human_agent.py      # Human interactive agent
├── engine/
│   └── engine.py           # SimulationEngine: turn loop, effects, win conditions
├── env/
│   ├── network.py          # Network, Node, Edge, Vulnerability, Service models
│   ├── actions.py          # ActionType enum, Action dataclass, ActionResolver
│   └── observation.py      # Partial observability — Red/Blue see different things
├── scenarios/
│   └── scenarios.py        # Pre-built topologies: corporate, ICS/OT, cloud, govdef
├── rl/
│   └── ppo_agent.py        # PPO reinforcement learning agent
└── cyberwar.spec           # PyInstaller build spec
```

---

## Game Modes

### Watch (AI vs AI Replay)
Select a scenario and agent types, then watch the battle play out as an animated network graph replay. See every action, node state change, and alert.

### Play (Human vs AI)
Take control of the Red team. On each turn you see:
- Your discovered network (fog of war — unknown nodes are hidden)
- Available actions and valid targets
- Outcome of your last action

Select an action, then select a target node if required — the Submit button enables automatically once your selection is complete. Blue AI defends each turn.

---

## Action Space

### Red (Attacker)
| Action | Effect |
|--------|--------|
| `scan` | Discover services & vulnerabilities on a node |
| `exploit` | Exploit a CVE; probability = CVSS/10 - patch penalty |
| `lateral_move` | Pivot from a compromised node to a neighbour |
| `privilege_esc` | Gain elevated privileges on a compromised node |
| `exfiltrate` | Steal data (25% progress per turn) |
| `persist` | Install backdoor (survives some restores) |
| `ddos` | Degrade target node services |

### Blue (Defender)
| Action | Effect |
|--------|--------|
| `monitor` | Watch node/edge; raises alert on Red activity |
| `patch` | Remove a CVE or increase patch level |
| `isolate` | Cut node from network |
| `restore` | Reset node to clean state |
| `deploy_honeypot` | Trap Red agents; triggers high alerts |
| `deploy_decoy` | Fake high-value target |
| `harden` | Increase patch level |
| `hunt` | Active threat hunt — reveals compromised nodes |
| `block_edge` | Firewall rule — permanently removes a network edge |

---

## Scenarios

| Scenario | Nodes | Description |
|----------|-------|-------------|
| `corporate` | 9 | Classic DMZ → internal pivot → Active Directory |
| `ics` | 7 | IT/OT convergence — HMI → PLC attack path |
| `cloud` | 7 | API Gateway → Lambda → RDS/S3/IAM |
| `govdef` | — | Government defence network |

---

## Observation System (Partial Observability)

**Red sees:** Only nodes it has scanned or compromised, plus their direct neighbours. No honeypot flags, no alert levels, no Blue plans.

**Blue sees:** All nodes at all times, alert levels, data exfil progress, honeypot status, and alerts generated by Red activity.

---

## Claude LLM Agent

### Setup

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

### How it works

`ClaudeAgent` uses native tool use (not JSON-in-text):

1. Each turn Claude receives a rich system prompt establishing its role and tactical doctrine
2. The current observation is formatted as structured markdown with node states, alert levels, and known vulnerabilities
3. Claude is given a `take_action` tool with a typed schema covering all valid actions
4. `tool_choice: "any"` forces Claude to always call the tool
5. Full conversation history is maintained across turns for situational memory
6. After each turn the engine feeds back the result (success/failure/detected)

### Model recommendations

| Model | Speed | Cost | Best for |
|-------|-------|------|----------|
| `claude-haiku-4-5-20251001` | Fast | Low | Development, many games |
| `claude-sonnet-4-6` | Medium | Medium | Balanced quality |
| `claude-opus-4-6` | Slow | High | Best strategy, showcases |

### Token usage estimates (per 20-turn game)

| Config | Input tokens | Output tokens | Approx cost |
|--------|-------------|---------------|-------------|
| Claude red + heuristic blue | ~25k | ~3k | ~$0.02 (Haiku) |
| Claude vs Claude | ~50k | ~6k | ~$0.04 (Haiku) |
| Claude vs Claude | ~50k | ~6k | ~$1.50 (Opus) |

---

## Building from Source

Requires Python 3.11 and PyInstaller.

**Mac:**
```bash
bash build.sh
# Output: dist/CyberWarSandbox.app
```

**Windows:**
```bat
build_win.bat
REM Output: dist\CyberWarSandbox\CyberWarSandbox.exe
```

### Automated builds via GitHub Actions

Every push to `main` automatically builds both Mac and Windows packages. Download the zips from the **Actions** tab → latest run → **Artifacts**.

To create a public release with download links:

```bash
git tag v2.0.1
git push origin v2.0.1
```

Or create a tag through the GitHub web UI under **Releases → Draft a new release**.

---

## Dependencies

```
flask
networkx
numpy
pyinstaller
anthropic  # optional, for Claude LLM agent
```

Install: `pip install -r requirements.txt`

---

## Win Conditions

```python
WinCondition(
    max_turns=30,
    red_score_thresh=20.0,   # Red wins if score >= this
    exfil_thresh=0.8,        # Red wins if any node >= 80% exfiltrated
)
```

---

## Extending the Framework

### Add a new action
1. Add entry to `ActionType` enum in `env/actions.py`
2. Implement `_your_action()` in `ActionResolver`
3. Add to dispatch dict in `ActionResolver.resolve()`
4. Handle effects in `engine/engine.py` `_apply_effects()`

### Add a new agent
Subclass `BaseAgent` and implement `act(obs: Observation) -> Action`.

### Add a custom scenario
```python
from env.network import Network, Node, Edge, NodeType, Service, Vulnerability, NodeState, Team

def my_scenario():
    net = Network(name="My Network")
    net.add_node(Node("entry", "Entry Point", NodeType.WORKSTATION,
                      state=NodeState(owner=Team.RED, compromised=True)))
    net.add_node(Node("target", "Database", NodeType.DATABASE,
                      services=[Service("postgres", 5432, "14.0")],
                      vulnerabilities=[Vulnerability("CVE-2022-XXXX", 9.0, "postgres")],
                      value=10))
    net.add_edge(Edge("entry", "target"))
    return net, "entry"
```
