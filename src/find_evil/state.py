from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict

from .contracts import (
    AuditLogEntry,
    BenchmarkResultRecord,
    ConfidenceRecord,
    EscalationDecisionRecord,
    FindingRecord,
    HypothesisRecord,
    NodeUpdate,
    ReportRecord,
    RelationshipGraphRecord,
    RemediationStepRecord,
)


class AgentState(TypedDict):
    evidence_file_paths: list[str]
    audit_trail_snapshot: FindingRecord
    evidence_integrity_report: dict[str, Any]
    raw_triage_findings: Annotated[list[FindingRecord], add]
    memory_findings: Annotated[list[FindingRecord], add]
    threat_intel_findings: Annotated[list[FindingRecord], add]
    active_vs_dormant_result: dict[str, Any]
    negative_space_findings: Annotated[list[FindingRecord], add]
    correlation_results: Annotated[list[FindingRecord], add]
    attack_technique_mappings: Annotated[list[dict[str, Any]], add]
    evidence_relationship_graph: RelationshipGraphRecord
    confidence_scores: Annotated[list[ConfidenceRecord], add]
    hypotheses: Annotated[list[HypothesisRecord], add]
    blast_radius_assessment: dict[str, Any]
    attacker_intent_summary: dict[str, Any]
    predicted_next_steps: Annotated[list[dict[str, Any]], add]
    attack_timeline: Annotated[list[dict[str, Any]], add]
    escalation_decision: EscalationDecisionRecord
    iocs: Annotated[list[dict[str, Any]], add]
    benchmark_results: BenchmarkResultRecord
    final_reports: Annotated[list[ReportRecord], add]
    remediation_steps: Annotated[list[RemediationStepRecord], add]
    self_correction_trace: Annotated[list[FindingRecord], add]
    iteration_count: int
    max_iterations: int
    retry_requested: bool
    audit_log: Annotated[list[AuditLogEntry], add]