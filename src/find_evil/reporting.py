from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _count_findings(state: Mapping[str, Any]) -> int:
    finding_keys = [
        "raw_triage_findings",
        "memory_findings",
        "threat_intel_findings",
        "negative_space_findings",
        "correlation_results",
    ]
    return sum(len(state.get(key, [])) for key in finding_keys)


def _average_confidence(state: Mapping[str, Any]) -> float:
    confidence_scores = [
        float(score.get("confidence", 0.0))
        for score in state.get("confidence_scores", [])
        if isinstance(score, dict)
    ]
    if not confidence_scores:
        return 0.0

    return round(sum(confidence_scores) / len(confidence_scores), 2)


def build_dual_audience_reports(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence_count = len(state.get("evidence_file_paths", []))
    finding_count = _count_findings(state)
    hypothesis_count = len(state.get("hypotheses", []))
    graph = state.get("evidence_relationship_graph", {})
    graph_node_count = int(graph.get("node_count", 0)) if isinstance(graph, dict) else 0
    average_confidence = _average_confidence(state)

    analyst_report = {
        "audience": "technical analyst",
        "title": "Find Evil analysis summary",
        "summary": (
            f"The scaffold observed {evidence_count} evidence path(s), {finding_count} finding(s), "
            f"and {graph_node_count} relationship graph node(s) at an average confidence of {average_confidence:.2f}."
        ),
        "sections": {
            "Evidence": {
                "evidence_count": evidence_count,
                "graph_nodes": graph_node_count,
                "read_only_boundary": True,
            },
            "Findings": {
                "finding_count": finding_count,
                "confidence_average": average_confidence,
            },
            "Hypotheses": {
                "hypothesis_count": hypothesis_count,
                "top_hypothesis": (state.get("hypotheses", [{}])[0] if state.get("hypotheses") else {}),
            },
            "Next steps": [
                "Attach a live SIFT adapter when the workstation is available.",
                "Replace placeholder analysis with tool-backed node implementations.",
                "Benchmark against a labeled forensic dataset once ground truth is loaded.",
            ],
        },
    }

    executive_report = {
        "audience": "executive brief",
        "title": "Find Evil status update",
        "summary": (
            "The agent skeleton is wired, it protects evidence by design, and it can now produce "
            "structured summaries while waiting for the SIFT environment."
        ),
        "sections": {
            "Situation": {
                "status": "scaffold_complete",
                "evidence_paths_loaded": evidence_count,
                "ground_truth_ready": False,
            },
            "Impact": {
                "confidence_average": average_confidence,
                "analysis_scope": "deterministic placeholder analysis until SIFT arrives",
            },
            "Actions": [
                "Load real case data into the read-only evidence boundary.",
                "Swap in SIFT-backed adapters one node at a time.",
                "Run the benchmark harness against a labeled dataset.",
            ],
        },
    }

    return [analyst_report, executive_report]


def build_remediation_playbook(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence_count = len(state.get("evidence_file_paths", []))
    hypothesis_count = len(state.get("hypotheses", []))

    steps = [
        {
            "priority": 1,
            "timeframe": "immediate",
            "action": "Preserve evidence read-only and avoid destructive operations.",
            "rationale": "The architecture must keep spoliation impossible by construction.",
        },
        {
            "priority": 2,
            "timeframe": "same day",
            "action": "Load disk and memory evidence paths into the adapter boundary.",
            "rationale": "The graph needs real inputs before tool-backed analysis can begin.",
        },
        {
            "priority": 3,
            "timeframe": "same day",
            "action": "Replace placeholder node bodies with SIFT-backed tool calls.",
            "rationale": "The graph is already wired; the remaining work is to attach the analysis hands.",
        },
        {
            "priority": 4,
            "timeframe": "next run",
            "action": "Benchmark the final pipeline against a labeled forensic dataset.",
            "rationale": "The hackathon scoring rewards accuracy, traceability, and self-correction.",
        },
    ]

    if evidence_count == 0:
        steps[1]["action"] = "Provide at least one disk image or memory capture path."
        steps[1]["rationale"] = "No evidence paths were supplied yet, so the graph cannot move beyond manifest-level processing."

    if hypothesis_count == 0:
        steps.append(
            {
                "priority": 5,
                "timeframe": "next run",
                "action": "Seed the hypothesis generator with a known-case dataset.",
                "rationale": "The higher-order reasoning layer needs evidence to rank competing theories.",
            }
        )

    return steps


def extract_iocs(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidate_iocs: list[dict[str, Any]] = []

    for evidence_path in state.get("evidence_file_paths", []):
        candidate_iocs.append(
            {
                "candidate_stix_type": "indicator",
                "ioc_type": "artifact_path",
                "value": evidence_path,
                "confidence": 0.35,
                "source": "evidence_manifest",
            }
        )

    for finding in state.get("confidence_scores", []):
        if not isinstance(finding, dict):
            continue

        confidence = float(finding.get("confidence", 0.0))
        if confidence >= 0.5 and finding.get("trace_id"):
            candidate_iocs.append(
                {
                    "candidate_stix_type": "indicator",
                    "ioc_type": "finding_trace",
                    "value": finding["trace_id"],
                    "confidence": confidence,
                    "source": finding.get("node", "unknown"),
                }
            )

    seen_values: set[str] = set()
    deduplicated_iocs: list[dict[str, Any]] = []
    for candidate_ioc in candidate_iocs:
        value = str(candidate_ioc["value"])
        if value in seen_values:
            continue
        seen_values.add(value)
        deduplicated_iocs.append(candidate_ioc)

    return deduplicated_iocs


def decide_escalation(state: Mapping[str, Any]) -> dict[str, Any]:
    evidence_count = len(state.get("evidence_file_paths", []))
    average_confidence = _average_confidence(state)
    high_confidence_findings = [
        score for score in state.get("confidence_scores", []) if isinstance(score, dict) and float(score.get("confidence", 0.0)) >= 0.75
    ]

    should_escalate = evidence_count > 0 and bool(high_confidence_findings) and average_confidence >= 0.5
    return {
        "should_escalate": should_escalate,
        "reason": (
            "Escalate if the graph produces high-confidence findings and the evidence set is non-empty."
            if should_escalate
            else "The scaffold is still operating at placeholder confidence, so it should not wake a human yet."
        ),
        "evidence_count": evidence_count,
        "average_confidence": average_confidence,
        "high_confidence_finding_count": len(high_confidence_findings),
    }


def build_accuracy_benchmark_summary(state: Mapping[str, Any]) -> dict[str, Any]:
    finding_count = _count_findings(state)
    placeholder_finding_count = sum(
        1
        for collection_key in [
            "raw_triage_findings",
            "memory_findings",
            "threat_intel_findings",
            "negative_space_findings",
            "correlation_results",
        ]
        for finding in state.get(collection_key, [])
        if isinstance(finding, dict) and finding.get("status") == "placeholder"
    )

    return {
        "status": "pending_ground_truth",
        "ground_truth_loaded": False,
        "finding_count": finding_count,
        "placeholder_finding_count": placeholder_finding_count,
        "false_positives": 0,
        "missed_artifacts": 0,
        "hallucinated_claims": 0,
        "note": "Ground truth datasets are not wired in yet, so this report is a scaffold-level placeholder.",
    }