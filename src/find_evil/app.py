from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from typing import Any, cast

from .graph import build_graph
from .state import AgentState


DEFAULT_COLLECTION_FIELDS: dict[str, list[Any]] = {
    "raw_triage_findings": [],
    "memory_findings": [],
    "threat_intel_findings": [],
    "negative_space_findings": [],
    "correlation_results": [],
    "attack_technique_mappings": [],
    "confidence_scores": [],
    "hypotheses": [],
    "predicted_next_steps": [],
    "attack_timeline": [],
    "iocs": [],
    "final_reports": [],
    "remediation_steps": [],
    "self_correction_trace": [],
    "audit_log": [],
}


DEFAULT_MAPPING_FIELDS: dict[str, dict[str, Any]] = {
    "audit_trail_snapshot": {},
    "evidence_integrity_report": {},
    "active_vs_dormant_result": {},
    "evidence_relationship_graph": {},
    "blast_radius_assessment": {},
    "attacker_intent_summary": {},
    "escalation_decision": {},
    "benchmark_results": {},
}


def build_initial_state(
    *,
    evidence_file_paths: Sequence[str] | None = None,
    max_iterations: int = 1,
    retry_requested: bool = False,
) -> AgentState:
    state = cast(
        dict[str, Any],
        {
            "evidence_file_paths": list(evidence_file_paths or []),
            "iteration_count": 0,
            "max_iterations": max(1, int(max_iterations)),
            "retry_requested": retry_requested,
            **{key: value.copy() for key, value in DEFAULT_COLLECTION_FIELDS.items()},
            **{key: value.copy() for key, value in DEFAULT_MAPPING_FIELDS.items()},
        },
    )

    return cast(AgentState, state)


def run_case(initial_state: AgentState | None = None) -> AgentState:
    graph = build_graph()
    state = initial_state if initial_state is not None else build_initial_state()
    return graph.invoke(state)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Find Evil LangGraph scaffold.")
    parser.add_argument(
        "--evidence",
        dest="evidence_file_paths",
        action="append",
        default=[],
        help="Evidence file path to seed into the initial state. Repeatable.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=1,
        help="Hard cap for the self-correction loop.",
    )
    parser.add_argument(
        "--retry-requested",
        action="store_true",
        help="Seed the graph so the self-correction router may repeat if the cap allows it.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    final_state = run_case(
        build_initial_state(
            evidence_file_paths=args.evidence_file_paths,
            max_iterations=args.max_iterations,
            retry_requested=args.retry_requested,
        )
    )
    print(json.dumps(final_state, indent=2, sort_keys=True))
    return 0