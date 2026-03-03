"""
agents/claude_agent.py
=======================
ClaudeAgent — a fully wired LLM agent powered by the Anthropic API.

Uses native tool_use (not JSON-in-text) so Claude can reason step by step,
then call a structured `take_action` tool. Maintains a per-game conversation
history so Claude builds up situational awareness across turns.

Requirements:
    pip install anthropic

Usage:
    from agents.claude_agent import ClaudeAgent
    from env.network import Team

    agent = ClaudeAgent(
        agent_id="red-claude",
        team=Team.RED,
        model="claude-opus-4-6",       # or claude-haiku-4-5-20251001 for speed/cost
        verbose=True,
    )
"""

from __future__ import annotations
import json
import os
import time
from typing import Optional

import anthropic

from env.network import Team
from env.actions import Action, ActionType
from env.observation import Observation
from agents.agents import BaseAgent


# ─────────────────────────────────────────────────────────────────────────────
# System prompts
# ─────────────────────────────────────────────────────────────────────────────

RED_SYSTEM_PROMPT = """You are an elite red-team operator conducting an authorized cyber wargame simulation. 
Your mission is to compromise as many high-value network nodes as possible, exfiltrate data, and achieve 
your objectives before the blue team locks you out.

TEAM: RED (attacker)
OBJECTIVE: Maximize your score by compromising nodes (especially high-value ones like databases and 
Active Directory), exfiltrating data, and maintaining persistence.

TACTICS:
- Start by exploiting visible vulnerabilities on reachable nodes
- Prioritize high-CVSS vulns (Log4Shell 10.0 > EternalBlue 9.3)
- After exploitation, immediately scan neighbors to expand your attack surface  
- Lateral movement from compromised nodes unlocks deeper network access
- Exfiltrate from high-value nodes (db_server, ad_server have value 8-10)
- Watch for blue team responses — if a node gets restored, re-exploit quickly
- Honeypots will burn you: if you trigger one, your alert level spikes

SCORING: +value for each node you compromise, +2×value for full data exfiltration.

Think tactically. Plan multiple steps ahead. Prioritize relentlessly."""

BLUE_SYSTEM_PROMPT = """You are a senior incident responder and blue-team defender in an authorized 
cyber wargame simulation. Your mission is to detect, contain, and eradicate the red team threat while 
keeping critical assets secure.

TEAM: BLUE (defender)
OBJECTIVE: Protect high-value nodes (databases, AD server), minimize data loss, and eliminate red 
team footholds.

TACTICS:
- Monitor high-value and high-traffic nodes early (they attract attackers)
- When alert levels rise on a node, hunt it immediately
- Isolate or restore compromised nodes as fast as possible
- Patch critical vulnerabilities preemptively (CVSS ≥ 9 first)
- Deploy honeypots on tempting paths to trap lateral movement
- Block monitored edges where you detect suspicious traffic
- Prioritize: restore > isolate > hunt > patch > monitor > harden

PRIORITY ORDER for response:
1. CONFIRMED compromise → restore (resets everything) or isolate (stops spread)
2. HIGH ALERT (>50) → hunt to confirm, then act
3. KNOWN VULNS on unpatched nodes → patch before red exploits
4. No immediate threat → monitor, harden, deploy honeypots

Think defensively. Every turn you don't act, the attacker advances."""

# ─────────────────────────────────────────────────────────────────────────────
# Tool definition — Claude calls this to take an action
# ─────────────────────────────────────────────────────────────────────────────

def _make_tool_definition(team: Team) -> dict:
    """Returns the take_action tool schema for the given team."""

    if team == Team.RED:
        action_enum = [
            "scan", "exploit", "lateral_move", "privilege_esc",
            "exfiltrate", "persist", "ddos", "pass"
        ]
        action_descriptions = {
            "scan":          "Probe a node to discover its services and vulnerabilities. Required before exploiting unseen nodes.",
            "exploit":       "Exploit a vulnerability on a target node. Provide cve_id in params.",
            "lateral_move":  "Pivot from a compromised node to an adjacent one. Provide from_node in params.",
            "privilege_esc": "Escalate to root/admin on a compromised node.",
            "exfiltrate":    "Steal data from a compromised node. Provide amount (0.0–1.0) in params.",
            "persist":       "Install a backdoor on a compromised node for resilience.",
            "ddos":          "Degrade services on a target node.",
            "pass":          "Skip this turn.",
        }
    else:
        action_enum = [
            "monitor", "patch", "isolate", "restore", "deploy_honeypot",
            "deploy_decoy", "harden", "hunt", "block_edge", "pass"
        ]
        action_descriptions = {
            "monitor":        "Watch a node or edge for anomalies. Increases alert sensitivity.",
            "patch":          "Fix a specific CVE on a node. Provide cve_id in params.",
            "isolate":        "Quarantine a node from the network. Stops lateral movement through it.",
            "restore":        "Reset a node to clean state from backup. Removes compromise.",
            "deploy_honeypot":"Set a trap on a node — any red team scan/exploit triggers a large alert.",
            "deploy_decoy":   "Create a fake high-value target to misdirect the attacker.",
            "harden":         "Increase a node's patch level, reducing exploit success probability.",
            "hunt":           "Actively search for compromise on a node. Confirms or clears suspicion.",
            "block_edge":     "Add a firewall rule permanently removing a network edge.",
            "pass":           "Skip this turn.",
        }

    action_list = "\n".join(
        f"  - {k}: {v}" for k, v in action_descriptions.items()
    )

    return {
        "name": "take_action",
        "description": (
            f"Submit your chosen action for this turn. You are on the {team.value.upper()} team.\n\n"
            f"Available actions:\n{action_list}\n\n"
            "Always call this tool exactly once per turn. Think through your strategy in your reasoning "
            "before calling the tool."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action_type": {
                    "type": "string",
                    "enum": action_enum,
                    "description": "The type of action to take."
                },
                "target_node": {
                    "type": "string",
                    "description": "The node ID to target. Required for most actions.",
                },
                "params": {
                    "type": "object",
                    "description": (
                        "Additional parameters. For exploit: {\"cve_id\": \"CVE-XXXX-YYYY\"}. "
                        "For lateral_move: {\"from_node\": \"node_id\"}. "
                        "For exfiltrate: {\"amount\": 0.25}. "
                        "For block_edge: target_node should be \"src,dst\"."
                    ),
                    "properties": {
                        "cve_id":    {"type": "string"},
                        "from_node": {"type": "string"},
                        "amount":    {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    },
                },
                "reasoning": {
                    "type": "string",
                    "description": "Brief explanation of why you chose this action (1-2 sentences).",
                },
            },
            "required": ["action_type"],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Observation → structured prompt
# ─────────────────────────────────────────────────────────────────────────────

def _obs_to_user_message(obs: Observation, team: Team, last_outcome: Optional[str] = None) -> str:
    lines = [
        f"## Turn {obs.turn} — Tactical Situation",
        f"**Score:** You={obs.red_score if team == Team.RED else obs.blue_score:.1f}  "
        f"Enemy={obs.blue_score if team == Team.RED else obs.red_score:.1f}",
        "",
    ]

    if last_outcome:
        lines += [f"**Last turn result:** {last_outcome}", ""]

    if obs.alerts:
        lines += ["### ⚠ ALERTS THIS TURN"]
        for a in obs.alerts:
            lines.append(f"  - {a}")
        lines.append("")

    lines.append("### Network State")

    for nid, n in obs.visible_nodes.items():
        flags = []
        if n.compromised:               flags.append("🔴 COMPROMISED")
        if n.isolated:                  flags.append("🔒 ISOLATED")
        if n.honeypot:                  flags.append("🍯 HONEYPOT")
        if n.alert_level and n.alert_level > 0:
            sev = "HIGH" if n.alert_level > 60 else "MED" if n.alert_level > 30 else "LOW"
            flags.append(f"⚡ ALERT={n.alert_level}({sev})")
        if n.known_vulns:               flags.append(f"🐛 VULNS={n.known_vulns}")
        if n.data_exfil and n.data_exfil > 0:
            flags.append(f"📤 EXFIL={n.data_exfil*100:.0f}%")
        if n.services:                  flags.append(f"services={n.services[:2]}")

        flag_str = "  ".join(flags) if flags else "secure"
        lines.append(f"  **{nid}** [{n.node_type}] — {flag_str}")

    if obs.known_edges:
        lines.append("")
        lines.append("### Known Connections")
        edge_strs = [f"{s}→{d}" for s, d in obs.known_edges[:20]]
        lines.append("  " + ", ".join(edge_strs))

    lines += [
        "",
        "Choose your action for this turn. Think step-by-step about the best move, then call `take_action`.",
    ]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# ClaudeAgent
# ─────────────────────────────────────────────────────────────────────────────

class ClaudeAgent(BaseAgent):
    """
    An agent backed by Claude via the Anthropic API.

    Each turn, Claude receives:
      - A system prompt establishing its role and objectives
      - The full conversation history (for situational memory)
      - The current observation as a structured user message
      - A tool definition for `take_action`

    Claude reasons, then calls take_action with a structured JSON payload.
    The agent parses the tool call and returns the corresponding Action.

    Parameters
    ----------
    agent_id:    Unique identifier string
    team:        Team.RED or Team.BLUE
    model:       Claude model string. Default: claude-haiku-4-5-20251001 (fast/cheap for games)
    api_key:     Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
    max_tokens:  Max tokens for Claude's response per turn. Default: 512
    verbose:     Print Claude's reasoning to stdout. Default: False
    start_node:  Required for RED agents (entry point into the network)
    """

    def __init__(
        self,
        team:       Team,
        model:      str  = "claude-haiku-4-5-20251001",
        api_key:    Optional[str] = None,
        max_tokens: int  = 512,
        verbose:    bool = False,
        start_node: Optional[str] = None,   # required for RED
        **kwargs,
    ):
        super().__init__(team=team, **kwargs)
        self.model      = model
        self.max_tokens = max_tokens
        self.verbose    = verbose
        self.start_node = start_node

        self.client     = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self.tool_def   = _make_tool_definition(team)
        self.sys_prompt = RED_SYSTEM_PROMPT if team == Team.RED else BLUE_SYSTEM_PROMPT

        # Persistent conversation history (cleared each game, maintained per turn)
        self.conv_history: list[dict] = []
        self._last_outcome: Optional[str] = None

        # Track call stats
        self.total_input_tokens  = 0
        self.total_output_tokens = 0
        self.total_api_calls     = 0

    def reset(self):
        """Clear conversation history for a new game."""
        self.conv_history  = []
        self._last_outcome = None

    def act(self, obs: Observation) -> Action:
        """Call Claude API to decide the next action."""
        user_msg = _obs_to_user_message(obs, self.team, self._last_outcome)

        # Append to conversation history
        self.conv_history.append({"role": "user", "content": user_msg})

        # Call the API
        try:
            response = self.client.messages.create(
                model      = self.model,
                max_tokens = self.max_tokens,
                system     = self.sys_prompt,
                tools      = [self.tool_def],
                tool_choice= {"type": "any"},   # force tool use every turn
                messages   = self.conv_history,
            )
        except anthropic.APIError as e:
            print(f"[ClaudeAgent/{self.agent_id}] API error: {e}")
            return self._pass()

        self.total_api_calls     += 1
        self.total_input_tokens  += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens

        # Extract reasoning text + tool call
        reasoning_text = ""
        tool_input     = None

        for block in response.content:
            if block.type == "text":
                reasoning_text = block.text.strip()
            elif block.type == "tool_use" and block.name == "take_action":
                tool_input = block.input

        if self.verbose and reasoning_text:
            team_label = "🔴 RED" if self.team == Team.RED else "🔵 BLUE"
            print(f"\n{team_label} [T{obs.turn}] {self.agent_id}:")
            print(f"  Reasoning: {reasoning_text[:200]}{'...' if len(reasoning_text) > 200 else ''}")

        # Add assistant response to history
        self.conv_history.append({"role": "assistant", "content": response.content})

        # Parse the tool call into an Action
        if not tool_input:
            if self.verbose:
                print(f"  ⚠ No tool call found, passing.")
            # Add a synthetic tool result so history stays valid
            self._append_tool_result(response, "pass", "No tool call — passing.")
            return self._pass()

        action = self._parse_tool_input(tool_input, obs)

        if self.verbose:
            print(f"  Action: {action.action_type.value} → {action.target_node or '—'}")
            if tool_input.get("reasoning"):
                print(f"  Reason: {tool_input['reasoning']}")

        # Append tool result placeholder to maintain valid conversation
        result_text = f"Action submitted: {action.action_type.value}"
        if action.target_node:
            result_text += f" on {action.target_node}"
        self._append_tool_result(response, action.action_type.value, result_text)

        return action

    def record_outcome(self, outcome_msg: str):
        """Called by the engine after resolving the action so Claude knows what happened."""
        self._last_outcome = outcome_msg

    def _append_tool_result(self, response, action_type: str, result: str):
        """Add a tool_result message to keep conversation history valid for multi-turn."""
        tool_use_id = None
        for block in response.content:
            if block.type == "tool_use" and block.name == "take_action":
                tool_use_id = block.id
                break
        if tool_use_id:
            self.conv_history.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": result,
                }],
            })

    def _parse_tool_input(self, tool_input: dict, obs: Observation) -> Action:
        """Convert Claude's take_action tool call into an Action object."""
        raw_type = tool_input.get("action_type", "pass")
        params   = tool_input.get("params") or {}

        # Validate action type
        try:
            action_type = ActionType(raw_type)
        except ValueError:
            if self.verbose:
                print(f"  ⚠ Unknown action type '{raw_type}', passing.")
            return self._pass()

        target_node = tool_input.get("target_node")

        # Validate target_node exists if provided
        if target_node and target_node not in obs.visible_nodes:
            if self.verbose:
                print(f"  ⚠ Target '{target_node}' not visible, picking best alternative.")
            # Pick most interesting visible node as fallback
            target_node = self._best_fallback_node(obs, action_type)

        # For lateral_move, ensure from_node is set
        if action_type == ActionType.LATERAL_MOVE and "from_node" not in params:
            compromised = obs.compromised_nodes()
            if compromised:
                params["from_node"] = compromised[0]

        return Action(
            action_type = action_type,
            actor_id    = self.agent_id,
            target_node = target_node,
            params      = params,
        )

    def _best_fallback_node(self, obs: Observation, action_type: ActionType) -> Optional[str]:
        """Choose a reasonable target when Claude's choice isn't visible."""
        nodes = list(obs.visible_nodes.keys())
        if not nodes:
            return None
        if action_type in (ActionType.EXPLOIT, ActionType.SCAN):
            # Prefer uncompromised nodes with vulns
            for nid in nodes:
                n = obs.node(nid)
                if n and n.known_vulns and not n.compromised:
                    return nid
        if action_type in (ActionType.RESTORE, ActionType.ISOLATE, ActionType.HUNT):
            for nid in nodes:
                n = obs.node(nid)
                if n and n.compromised:
                    return nid
        return nodes[0]

    def stats_summary(self) -> str:
        return (
            f"ClaudeAgent({self.agent_id}) stats: "
            f"calls={self.total_api_calls} "
            f"in_tokens={self.total_input_tokens} "
            f"out_tokens={self.total_output_tokens}"
        )
