"""
Hellcat Knowledge Graph Engine
==============================
In-memory graph of entities (targets, services, vulns, credentials)
and relationships discovered during penetration testing.
Supports BFS multi-path discovery and optional SQLite persistence.
Ported from AutoRedTeam-Orchestrator core/knowledge/.
"""
from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Graph primitives
# ---------------------------------------------------------------------------

@dataclass
class Entity:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    type: str = ""          # target, service, vulnerability, credential, cloud_resource
    name: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.type, "name": self.name,
                "properties": self.properties}


@dataclass
class Relationship:
    source_id: str = ""
    target_id: str = ""
    rel_type: str = ""      # HOSTS, HAS_VULN, OBTAINED_FROM, CONNECTS_TO, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Knowledge Manager
# ---------------------------------------------------------------------------

class KnowledgeManager:
    """In-memory knowledge graph with BFS path discovery."""

    def __init__(self) -> None:
        self._entities: Dict[str, Entity] = {}
        self._relationships: List[Relationship] = []
        self._adjacency: Dict[str, List[str]] = {}    # entity_id -> [connected ids]
        self._success_rates: Dict[str, float] = {}     # path_hash -> rate

    # -- Entity CRUD ---------------------------------------------------------

    def store_entity(self, entity_type: str, name: str,
                     properties: Optional[Dict[str, Any]] = None) -> str:
        e = Entity(type=entity_type, name=name, properties=properties or {})
        self._entities[e.id] = e
        self._adjacency.setdefault(e.id, [])
        return e.id

    def store_target(self, address: str, target_type: str = "",
                     properties: Optional[Dict[str, Any]] = None) -> str:
        props = {"address": address, "target_type": target_type, **(properties or {})}
        return self.store_entity("target", address, props)

    def store_service(self, target_id: str, port: int, service: str,
                      properties: Optional[Dict[str, Any]] = None) -> str:
        sid = self.store_entity("service", f"{service}:{port}", {"port": port, "service": service, **(properties or {})})
        self.add_relationship(target_id, sid, "HOSTS")
        return sid

    def store_vulnerability(self, target_id: str, vuln_name: str, severity: str = "medium",
                            properties: Optional[Dict[str, Any]] = None) -> str:
        vid = self.store_entity("vulnerability", vuln_name, {"severity": severity, **(properties or {})})
        self.add_relationship(target_id, vid, "HAS_VULN")
        return vid

    def store_credential(self, source_id: str, username: str,
                         cred_type: str = "password",
                         properties: Optional[Dict[str, Any]] = None) -> str:
        cid = self.store_entity("credential", username, {"cred_type": cred_type, **(properties or {})})
        self.add_relationship(source_id, cid, "OBTAINED_FROM")
        return cid

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        return self._entities.get(entity_id)

    def get_entities_by_type(self, entity_type: str) -> List[Entity]:
        return [e for e in self._entities.values() if e.type == entity_type]

    # -- Relationships -------------------------------------------------------

    def add_relationship(self, source_id: str, target_id: str, rel_type: str,
                         properties: Optional[Dict[str, Any]] = None) -> None:
        rel = Relationship(source_id=source_id, target_id=target_id,
                           rel_type=rel_type, properties=properties or {})
        self._relationships.append(rel)
        self._adjacency.setdefault(source_id, []).append(target_id)
        self._adjacency.setdefault(target_id, []).append(source_id)

    def get_relationships(self, entity_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        rels = [r for r in self._relationships
                if r.source_id == entity_id or r.target_id == entity_id]
        if rel_type:
            rels = [r for r in rels if r.rel_type == rel_type]
        return rels

    # -- BFS path discovery --------------------------------------------------

    def get_attack_paths(self, start_id: str, goal_id: str,
                         max_depth: int = 10) -> List[List[str]]:
        """BFS — find all paths from start to goal (up to max_depth)."""
        if start_id not in self._entities or goal_id not in self._entities:
            return []

        paths: List[List[str]] = []
        queue: deque[Tuple[str, List[str]]] = deque([(start_id, [start_id])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if current == goal_id:
                paths.append(path)
                continue
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))

        return paths

    # -- Similarity ----------------------------------------------------------

    def find_similar_targets(self, entity_id: str) -> List[Tuple[str, float]]:
        """Find targets with overlapping services / vulns."""
        ref = self._entities.get(entity_id)
        if not ref or ref.type != "target":
            return []

        ref_neighbors: Set[str] = set(self._adjacency.get(entity_id, []))
        scored: List[Tuple[str, float]] = []
        for eid, e in self._entities.items():
            if e.type == "target" and eid != entity_id:
                neighbors = set(self._adjacency.get(eid, []))
                overlap = len(ref_neighbors & neighbors)
                union = len(ref_neighbors | neighbors)
                score = overlap / union if union else 0.0
                if score > 0:
                    scored.append((eid, score))
        return sorted(scored, key=lambda x: x[1], reverse=True)

    # -- Success rate tracking -----------------------------------------------

    def record_success(self, path: List[str], success: bool) -> None:
        key = "->".join(path)
        prev = self._success_rates.get(key, 0.5)
        # Exponential moving average
        self._success_rates[key] = prev * 0.7 + (1.0 if success else 0.0) * 0.3

    def get_success_rate(self, path: List[str]) -> float:
        return self._success_rates.get("->".join(path), 0.5)

    # -- Stats ---------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        for e in self._entities.values():
            type_counts[e.type] = type_counts.get(e.type, 0) + 1
        return {
            "total_entities": len(self._entities),
            "total_relationships": len(self._relationships),
            "entity_types": type_counts,
            "tracked_paths": len(self._success_rates),
        }

    def clear(self) -> None:
        self._entities.clear()
        self._relationships.clear()
        self._adjacency.clear()
        self._success_rates.clear()
