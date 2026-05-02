from __future__ import annotations

from typing import Any, NotRequired, TypedDict

from .evidence import EvidenceIntegrityReport


class AuditLogEntry(TypedDict, total=False):
    timestamp: str
    node: str
    event: str
    iteration_count: int
    max_iterations: int
    details: dict[str, Any]


class FindingRecord(TypedDict):
    node: str
    layer: int
    summary: str
    status: str
    confidence: float
    trace_id: str
    iteration_count: int
    iteration_count_after: NotRequired[int]
    max_iterations: int
    retry_requested: bool
    source_artifacts: list[str]
    details: dict[str, Any]


class HypothesisRecord(TypedDict):
    name: str
    priority: int
    status: str
    rationale: str
    next_test: str


class ReportRecord(TypedDict):
    audience: str
    title: str
    summary: str
    sections: dict[str, Any]


class RelationshipGraphRecord(TypedDict):
    node_count: int
    edge_count: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    summary: str


class ConfidenceRecord(TypedDict):
    node: str
    trace_id: str
    source_collection: str
    confidence: float
    evidence_count: int
    rationale: list[str]


class EscalationDecisionRecord(TypedDict):
    should_escalate: bool
    reason: str
    evidence_count: int
    average_confidence: float
    high_confidence_finding_count: int


class BenchmarkResultRecord(TypedDict):
    status: str
    ground_truth_loaded: bool
    finding_count: int
    placeholder_finding_count: int
    false_positives: int
    missed_artifacts: int
    hallucinated_claims: int
    note: str


class RemediationStepRecord(TypedDict):
    priority: int
    timeframe: str
    action: str
    rationale: str


class NodeUpdate(TypedDict, total=False):
    audit_trail_snapshot: FindingRecord
    evidence_integrity_report: EvidenceIntegrityReport
    raw_triage_findings: list[FindingRecord]
    memory_findings: list[FindingRecord]
    threat_intel_findings: list[FindingRecord]
    active_vs_dormant_result: dict[str, Any]
    negative_space_findings: list[FindingRecord]
    correlation_results: list[FindingRecord]
    attack_technique_mappings: list[dict[str, Any]]
    evidence_relationship_graph: RelationshipGraphRecord
    confidence_scores: list[ConfidenceRecord]
    hypotheses: list[HypothesisRecord]
    blast_radius_assessment: dict[str, Any]
    attacker_intent_summary: dict[str, Any]
    predicted_next_steps: list[dict[str, Any]]
    attack_timeline: list[dict[str, Any]]
    escalation_decision: EscalationDecisionRecord
    iocs: list[dict[str, Any]]
    benchmark_results: BenchmarkResultRecord
    final_reports: list[ReportRecord]
    remediation_steps: list[RemediationStepRecord]
    self_correction_trace: list[FindingRecord]
    iteration_count: int
    audit_log: list[AuditLogEntry]