from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


class ContractViolationError(ValueError):
    """Raised when state or node output violates the graph contract."""


STATE_SEQUENCE_KEYS = (
    "evidence_file_paths",
    "raw_triage_findings",
    "memory_findings",
    "threat_intel_findings",
    "negative_space_findings",
    "correlation_results",
    "attack_technique_mappings",
    "confidence_scores",
    "hypotheses",
    "predicted_next_steps",
    "attack_timeline",
    "iocs",
    "final_reports",
    "remediation_steps",
    "self_correction_trace",
    "audit_log",
)

STATE_MAPPING_KEYS = (
    "audit_trail_snapshot",
    "evidence_integrity_report",
    "active_vs_dormant_result",
    "evidence_relationship_graph",
    "blast_radius_assessment",
    "attacker_intent_summary",
    "escalation_decision",
    "benchmark_results",
)

STATE_SCALAR_KEYS = (
    "iteration_count",
    "max_iterations",
    "retry_requested",
)

STATE_KEYS = STATE_SEQUENCE_KEYS + STATE_MAPPING_KEYS + STATE_SCALAR_KEYS

NODE_UPDATE_KEYS = STATE_KEYS

SEQUENCE_VALUE_KEYS = {
    "raw_triage_findings",
    "memory_findings",
    "threat_intel_findings",
    "negative_space_findings",
    "correlation_results",
    "attack_technique_mappings",
    "confidence_scores",
    "hypotheses",
    "predicted_next_steps",
    "attack_timeline",
    "iocs",
    "final_reports",
    "remediation_steps",
    "self_correction_trace",
    "audit_log",
}


def build_initial_state_payload(
    *,
    evidence_file_paths: Sequence[str] | None = None,
    max_iterations: int = 1,
    retry_requested: bool = False,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "evidence_file_paths": list(evidence_file_paths or []),
        "iteration_count": 0,
        "max_iterations": max(1, int(max_iterations)),
        "retry_requested": retry_requested,
    }

    for key in STATE_SEQUENCE_KEYS:
        if key in STATE_SEQUENCE_KEYS and key not in state:
            state[key] = []

    for key in STATE_MAPPING_KEYS:
        state[key] = {}

    return state


def validate_initial_state(state: Mapping[str, Any]) -> None:
    missing_keys = [key for key in STATE_KEYS if key not in state]
    if missing_keys:
        raise ContractViolationError(f"Initial state is missing required keys: {missing_keys}")

    for key in STATE_SEQUENCE_KEYS:
        if not isinstance(state.get(key), list):
            raise ContractViolationError(f"Initial state key {key!r} must be a list.")

    for key in STATE_MAPPING_KEYS:
        if not isinstance(state.get(key), dict):
            raise ContractViolationError(f"Initial state key {key!r} must be a mapping.")

    if not isinstance(state.get("iteration_count"), int):
        raise ContractViolationError("Initial state key 'iteration_count' must be an int.")
    if not isinstance(state.get("max_iterations"), int):
        raise ContractViolationError("Initial state key 'max_iterations' must be an int.")
    if not isinstance(state.get("retry_requested"), bool):
        raise ContractViolationError("Initial state key 'retry_requested' must be a bool.")


def validate_node_output(node_name: str, output: Mapping[str, Any]) -> dict[str, Any]:
    unknown_keys = sorted(set(output) - set(NODE_UPDATE_KEYS))
    if unknown_keys:
        raise ContractViolationError(
            f"Node {node_name!r} returned unknown state key(s): {unknown_keys}"
        )

    if "iteration_count" in output and not isinstance(output["iteration_count"], int):
        raise ContractViolationError(f"Node {node_name!r} must return an int iteration_count.")

    if "retry_requested" in output and not isinstance(output["retry_requested"], bool):
        raise ContractViolationError(f"Node {node_name!r} must return a bool retry_requested flag.")

    for key in output:
        if key in SEQUENCE_VALUE_KEYS and not isinstance(output[key], list):
            raise ContractViolationError(f"Node {node_name!r} must return a list for {key!r}.")

        if key in STATE_MAPPING_KEYS and not isinstance(output[key], dict):
            raise ContractViolationError(f"Node {node_name!r} must return a mapping for {key!r}.")

    return dict(output)