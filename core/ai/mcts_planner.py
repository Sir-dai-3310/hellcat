"""
Hellcat MCTS Attack Path Planner
================================
Monte Carlo Tree Search with UCB1 exploration for optimal attack sequencing.
Ported from AutoRedTeam-Orchestrator core/mcts_planner.py.
Extended with identity_attack / lotl / cloud_abuse action types.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from hellcat.core.models import Action, ActionType, AttackState

DEFAULT_EXPLORATION = 1.414


# ---------------------------------------------------------------------------
# MCTS Node
# ---------------------------------------------------------------------------

class MCTSNode:
    __slots__ = ("state", "action", "parent", "children",
                 "visits", "total_reward", "untried_actions")

    def __init__(self, state: AttackState, action: Optional[Action] = None,
                 parent: Optional[MCTSNode] = None) -> None:
        self.state = state
        self.action = action
        self.parent = parent
        self.children: List[MCTSNode] = []
        self.visits: int = 0
        self.total_reward: float = 0.0
        self.untried_actions: Optional[List[Action]] = None

    @property
    def average_reward(self) -> float:
        return self.total_reward / self.visits if self.visits else 0.0

    def ucb1(self, c: float = DEFAULT_EXPLORATION) -> float:
        if self.visits == 0:
            return float("inf")
        exploit = self.average_reward
        explore = c * math.sqrt(math.log(self.parent.visits) / self.visits) if self.parent else 0.0
        return exploit + explore

    def best_child(self, c: float = DEFAULT_EXPLORATION) -> Optional[MCTSNode]:
        if not self.children:
            return None
        return max(self.children, key=lambda n: n.ucb1(c))

    def best_action_child(self) -> Optional[MCTSNode]:
        if not self.children:
            return None
        return max(self.children, key=lambda n: n.average_reward)


# ---------------------------------------------------------------------------
# Action Generator
# ---------------------------------------------------------------------------

SERVICE_ACTIONS: Dict[str, List[Action]] = {
    "http": [
        Action(ActionType.WEB_SCAN, "web_vuln_scan", "nuclei"),
        Action(ActionType.VULN_SCAN, "sqli_scan", "sqlmap"),
        Action(ActionType.VULN_SCAN, "xss_scan", "xsstrike"),
        Action(ActionType.BRUTE_FORCE, "dir_brute", "ffuf"),
    ],
    "ssh": [
        Action(ActionType.BRUTE_FORCE, "ssh_brute", "hydra"),
        Action(ActionType.LATERAL_MOVE, "ssh_lateral", "paramiko"),
    ],
    "smb": [
        Action(ActionType.LATERAL_MOVE, "smb_pth", "impacket"),
        Action(ActionType.CREDENTIAL_DUMP, "smb_enum", "enum4linux"),
    ],
    "mysql": [
        Action(ActionType.BRUTE_FORCE, "mysql_brute", "hydra"),
        Action(ActionType.EXPLOIT, "mysql_udf", "sqlmap"),
    ],
    "rdp": [
        Action(ActionType.BRUTE_FORCE, "rdp_brute", "hydra"),
    ],
}

# 2026 tactics
ADVANCED_ACTIONS: List[Action] = [
    Action(ActionType.IDENTITY_ATTACK, "aitm_proxy", "evilginx", risk_score=0.8),
    Action(ActionType.IDENTITY_ATTACK, "mfa_fatigue", "custom", risk_score=0.7),
    Action(ActionType.LOTL, "powershell_cradle", "powershell", risk_score=0.6),
    Action(ActionType.LOTL, "wmi_exec", "wmic", risk_score=0.5),
    Action(ActionType.CLOUD_ABUSE, "iam_enum", "prowler", risk_score=0.4),
    Action(ActionType.EVASION, "amsi_bypass", "custom", risk_score=0.7),
    Action(ActionType.PERSISTENCE, "scheduled_task", "schtasks", risk_score=0.6),
]


class ActionGenerator:
    def generate(self, state: AttackState) -> List[Action]:
        actions: List[Action] = []
        # Port/service-based actions
        for port, svc in state.open_ports.items():
            svc_key = svc.lower().split("/")[0]
            actions.extend(SERVICE_ACTIONS.get(svc_key, []))

        # If we already have credentials, add lateral + privesc
        if state.credentials:
            actions.append(Action(ActionType.LATERAL_MOVE, "auto_lateral", "hellcat"))
            actions.append(Action(ActionType.PRIVESC, "privesc_check", "linpeas"))

        # If access_level >= 1, add advanced actions
        if state.access_level >= 1:
            actions.extend(ADVANCED_ACTIONS)

        # Always available: port scan if few ports known
        if len(state.open_ports) < 5:
            actions.append(Action(ActionType.PORT_SCAN, "full_port_scan", "nmap"))

        # Deduplicate
        seen = set()
        unique: List[Action] = []
        for a in actions:
            key = (a.type, a.name)
            if key not in seen and a.name not in state.completed_actions:
                seen.add(key)
                unique.append(a)
        return unique


# ---------------------------------------------------------------------------
# Attack Simulator
# ---------------------------------------------------------------------------

BASE_SUCCESS: Dict[ActionType, float] = {
    ActionType.PORT_SCAN: 0.95,
    ActionType.SERVICE_DETECT: 0.90,
    ActionType.VULN_SCAN: 0.70,
    ActionType.WEB_SCAN: 0.65,
    ActionType.BRUTE_FORCE: 0.30,
    ActionType.EXPLOIT: 0.40,
    ActionType.PRIVESC: 0.35,
    ActionType.LATERAL_MOVE: 0.45,
    ActionType.DATA_EXFIL: 0.60,
    ActionType.CREDENTIAL_DUMP: 0.50,
    ActionType.IDENTITY_ATTACK: 0.35,
    ActionType.LOTL: 0.55,
    ActionType.CLOUD_ABUSE: 0.40,
    ActionType.PERSISTENCE: 0.65,
    ActionType.EVASION: 0.50,
}


class AttackSimulator:
    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    def simulate_action(self, state: AttackState, action: Action) -> AttackState:
        new_state = state.clone()
        rate = BASE_SUCCESS.get(action.type, 0.5)
        if self._rng.random() < rate:
            self._apply_success(new_state, action)
        new_state.completed_actions.add(action.name)
        return new_state

    def _apply_success(self, state: AttackState, action: Action) -> None:
        if action.type == ActionType.PORT_SCAN:
            for p in [22, 80, 443, 3306, 8080]:
                if p not in state.open_ports:
                    state.add_open_port(p, "unknown")
                    break
        elif action.type in (ActionType.VULN_SCAN, ActionType.WEB_SCAN):
            state.add_vulnerability({"type": action.name, "severity": "high"})
        elif action.type == ActionType.BRUTE_FORCE:
            state.add_credential({"username": "admin", "source": action.name})
        elif action.type == ActionType.EXPLOIT:
            state.access_level = max(state.access_level, 1)
        elif action.type == ActionType.PRIVESC:
            state.access_level = max(state.access_level, 3)
        elif action.type == ActionType.LATERAL_MOVE:
            state.access_level = max(state.access_level, 2)
        elif action.type == ActionType.CREDENTIAL_DUMP:
            state.add_credential({"username": "dumped", "source": action.name})


# ---------------------------------------------------------------------------
# MCTS Planner
# ---------------------------------------------------------------------------

class MCTSPlanner:
    def __init__(self, exploration_weight: float = DEFAULT_EXPLORATION,
                 max_depth: int = 10, seed: Optional[int] = None) -> None:
        self.exploration = exploration_weight
        self.max_depth = max_depth
        self.generator = ActionGenerator()
        self.simulator = AttackSimulator(seed)

    def plan(self, initial_state: AttackState, iterations: int = 100) -> Dict[str, Any]:
        root = MCTSNode(initial_state)
        root.untried_actions = self.generator.generate(initial_state)

        for _ in range(iterations):
            node = self._select(root)
            node = self._expand(node)
            reward = self._simulate(node)
            self._backpropagate(node, reward)

        best_path = self._extract_best_path(root)
        return {
            "recommended_actions": best_path,
            "iterations": iterations,
            "root_visits": root.visits,
            "root_reward": root.average_reward,
        }

    def _select(self, node: MCTSNode) -> MCTSNode:
        depth = 0
        while node.children and depth < self.max_depth:
            if node.untried_actions:
                return node
            child = node.best_child(self.exploration)
            if child is None:
                break
            node = child
            depth += 1
        return node

    def _expand(self, node: MCTSNode) -> MCTSNode:
        if node.untried_actions is None:
            node.untried_actions = self.generator.generate(node.state)
        if not node.untried_actions:
            return node
        action = node.untried_actions.pop()
        new_state = self.simulator.simulate_action(node.state, action)
        child = MCTSNode(new_state, action=action, parent=node)
        child.untried_actions = self.generator.generate(new_state)
        node.children.append(child)
        return child

    def _simulate(self, node: MCTSNode) -> float:
        state = node.state.clone()
        depth = 0
        while not state.is_terminal() and depth < self.max_depth:
            actions = self.generator.generate(state)
            if not actions:
                break
            action = random.choice(actions)
            state = self.simulator.simulate_action(state, action)
            depth += 1
        return state.reward()

    def _backpropagate(self, node: MCTSNode, reward: float) -> None:
        current: Optional[MCTSNode] = node
        while current is not None:
            current.visits += 1
            current.total_reward += reward
            current = current.parent

    def _extract_best_path(self, root: MCTSNode) -> List[Tuple[str, int, float]]:
        path: List[Tuple[str, int, float]] = []
        node = root
        while node.children:
            best = node.best_action_child()
            if best is None or best.action is None:
                break
            path.append((best.action.name, best.visits, best.average_reward))
            node = best
        return path
