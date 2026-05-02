from __future__ import annotations

from collections.abc import Iterable, Sequence
from collections.abc import Mapping
from typing import Any

from .evidence import build_disk_triage_summary, classify_evidence_path


FINDING_COLLECTION_KEYS = [
    "raw_triage_findings",
    "memory_findings",
    "threat_intel_findings",
    "negative_space_findings",
    "correlation_results",
]


def _iter_findings(state: Mapping[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for collection_key in FINDING_COLLECTION_KEYS:
        for finding in state.get(collection_key, []):
            if isinstance(finding, dict):
                yield collection_key, finding


def build_evidence_relationship_graph(state: Mapping[str, Any]) -> dict[str, Any]:
    evidence_paths = list(state.get("evidence_file_paths", []))
    artifact_nodes: dict[str, dict[str, Any]] = {}
    finding_nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for path in evidence_paths:
        artifact_nodes[path] = {
            "id": path,
            "kind": "artifact",
            "path": path,
            "artifact_type": classify_evidence_path(path),
            "read_only": True,
        }

    for collection_key, finding in _iter_findings(state):
        finding_id = str(finding.get("trace_id") or f"{collection_key}:{len(finding_nodes) + 1}")
        source_artifacts = list(finding.get("source_artifacts", []))

        finding_nodes.append(
            {
                "id": finding_id,
                "kind": "finding",
                "collection": collection_key,
                "node": finding.get("node", collection_key),
                "layer": finding.get("layer", 0),
                "status": finding.get("status", "unknown"),
                "confidence": finding.get("confidence", 0.0),
                "source_artifacts": source_artifacts,
            }
        )

        for artifact_path in source_artifacts:
            if artifact_path not in artifact_nodes:
                artifact_nodes[artifact_path] = {
                    "id": artifact_path,
                    "kind": "artifact",
                    "path": artifact_path,
                    "artifact_type": classify_evidence_path(artifact_path),
                    "read_only": True,
                }

            edges.append(
                {
                    "source": artifact_path,
                    "target": finding_id,
                    "relationship": "supports",
                }
            )

    return {
        "node_count": len(artifact_nodes) + len(finding_nodes),
        "edge_count": len(edges),
        "nodes": list(artifact_nodes.values()) + finding_nodes,
        "edges": edges,
        "summary": (
            f"Built a relationship graph with {len(artifact_nodes)} artifact node(s), "
            f"{len(finding_nodes)} finding node(s), and {len(edges)} edge(s)."
        ),
    }


def calibrate_confidence_scores(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    confidence_scores: list[dict[str, Any]] = []

    for collection_key, finding in _iter_findings(state):
        evidence_count = len(list(finding.get("source_artifacts", [])))
        base_confidence = 0.10 + min(evidence_count, 3) * 0.15
        if int(finding.get("layer", 0)) == 0:
            base_confidence += 0.05
        if finding.get("status") != "placeholder":
            base_confidence += 0.10

        confidence_scores.append(
            {
                "node": finding.get("node", collection_key),
                "trace_id": finding.get("trace_id"),
                "source_collection": collection_key,
                "confidence": round(min(base_confidence, 0.95), 2),
                "evidence_count": evidence_count,
                "rationale": [
                    (
                        "no supporting artifacts yet"
                        if evidence_count == 0
                        else f"supported by {evidence_count} artifact(s)"
                    ),
                    f"status={finding.get('status', 'unknown')}",
                ],
            }
        )

    return confidence_scores


def rank_hypotheses(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    triage_summary = build_disk_triage_summary(state.get("evidence_file_paths", []))
    disk_image_count = triage_summary["disk_image_count"]
    memory_capture_count = triage_summary["memory_capture_count"]

    if disk_image_count == 0 and memory_capture_count == 0:
        return [
            {
                "name": "Await evidence inputs",
                "priority": 1,
                "status": "pending",
                "rationale": "No disk image or memory capture has been supplied yet.",
                "next_test": "Provide a disk image or memory capture path so the analysis can begin.",
            }
        ]

    hypotheses: list[dict[str, Any]] = []

    if disk_image_count > 0 and memory_capture_count > 0:
        hypotheses.append(
            {
                "name": "Correlate disk and memory evidence",
                "priority": 1,
                "status": "pending",
                "rationale": "Both disk and memory evidence are available, so cross-correlation is the highest-value next step.",
                "next_test": "Compare the triage manifest to memory-derived process and connection artifacts.",
            }
        )

        hypotheses.append(
            {
                "name": "Determine whether the adversary is still active",
                "priority": 2,
                "status": "pending",
                "rationale": "Memory evidence can reveal live processes, sockets, and credentials that disk alone cannot.",
                "next_test": "Check memory-derived artifacts for live connections and active execution traces.",
            }
        )
    elif disk_image_count > 0:
        hypotheses.append(
            {
                "name": "Disk-image triage first",
                "priority": 1,
                "status": "pending",
                "rationale": "Only a disk image is present, so static triage should establish the initial evidence picture.",
                "next_test": "Extract the disk manifest and identify artifacts that deserve deeper inspection later.",
            }
        )
    else:
        hypotheses.append(
            {
                "name": "Memory-capture triage first",
                "priority": 1,
                "status": "pending",
                "rationale": "Only a memory capture is present, so live-state inspection should anchor the investigation.",
                "next_test": "Inspect the memory manifest for live processes, open connections, and credential material.",
            }
        )

    return hypotheses