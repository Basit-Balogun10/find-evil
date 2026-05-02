from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from . import nodes
from .state import AgentState


NODE_SEQUENCE = [
    "audit_trail",
    "evidence_integrity",
    "basic_disk_triage",
    "memory_analysis",
    "threat_intel_lookup",
    "active_vs_dormant_determination",
    "negative_space_reasoning",
    "disk_memory_correlation",
    "mitre_mapping",
    "evidence_relationship_graph",
    "confidence_calibration",
    "hypothesis_driven_investigation",
    "blast_radius_assessment",
    "attacker_perspective",
    "predictive_next_step_reasoning",
    "timeline_reconstruction",
    "escalation_decision",
    "ioc_extraction",
    "accuracy_benchmarking",
    "dual_audience_reporting",
    "remediation_playbook",
    "self_correction_loop",
]


def route_after_self_correction(state: AgentState) -> str:
    iteration_count = int(state.get("iteration_count", 0))
    max_iterations = max(1, int(state.get("max_iterations", 1)))
    retry_requested = bool(state.get("retry_requested", False))

    if retry_requested and iteration_count < max_iterations:
        return "repeat"

    return "end"


def build_graph() -> Any:
    workflow = StateGraph(AgentState)

    for node_name in NODE_SEQUENCE:
        workflow.add_node(node_name, getattr(nodes, node_name))

    workflow.add_edge(START, NODE_SEQUENCE[0])

    for current_node, next_node in zip(NODE_SEQUENCE[:-2], NODE_SEQUENCE[1:-1], strict=False):
        workflow.add_edge(current_node, next_node)

    workflow.add_edge("remediation_playbook", "self_correction_loop")
    workflow.add_conditional_edges(
        "self_correction_loop",
        route_after_self_correction,
        {
            "repeat": NODE_SEQUENCE[0],
            "end": END,
        },
    )

    return workflow.compile()