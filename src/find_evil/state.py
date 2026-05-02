from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict


class AgentState(TypedDict):
    evidence_file_paths: list[str]
    audit_trail_snapshot: dict[str, Any]
    evidence_integrity_report: dict[str, Any]
    raw_triage_findings: Annotated[list[dict[str, Any]], add]
    memory_findings: Annotated[list[dict[str, Any]], add]
    threat_intel_findings: Annotated[list[dict[str, Any]], add]
    active_vs_dormant_result: dict[str, Any]
    negative_space_findings: Annotated[list[dict[str, Any]], add]
    correlation_results: Annotated[list[dict[str, Any]], add]
    attack_technique_mappings: Annotated[list[dict[str, Any]], add]
    evidence_relationship_graph: dict[str, Any]
    confidence_scores: Annotated[list[dict[str, Any]], add]
    hypotheses: Annotated[list[dict[str, Any]], add]
    blast_radius_assessment: dict[str, Any]
    attacker_intent_summary: dict[str, Any]
    predicted_next_steps: Annotated[list[dict[str, Any]], add]
    attack_timeline: Annotated[list[dict[str, Any]], add]
    escalation_decision: dict[str, Any]
    iocs: Annotated[list[dict[str, Any]], add]
    benchmark_results: dict[str, Any]
    final_reports: Annotated[list[dict[str, Any]], add]
    remediation_steps: Annotated[list[dict[str, Any]], add]
    self_correction_trace: Annotated[list[dict[str, Any]], add]
    iteration_count: int
    max_iterations: int
    retry_requested: bool
    audit_log: Annotated[list[dict[str, Any]], add]