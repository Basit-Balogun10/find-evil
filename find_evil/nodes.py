from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .adapters import build_default_adapter
from .audit import AUDIT_LOGGER
from .evidence import build_disk_triage_summary, build_evidence_integrity_report
from .reasoning import build_evidence_relationship_graph, calibrate_confidence_scores, rank_hypotheses
from .state import AgentState


NodeFunction = Callable[[AgentState], dict[str, Any]]


NODE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "audit_trail": {
        "layer": 0,
        "state_key": "audit_trail_snapshot",
        "mode": "replace",
        "summary": "Initialize the audit trail and record the current execution context.",
    },
    "evidence_integrity": {
        "layer": 0,
        "state_key": "evidence_integrity_report",
        "mode": "replace",
        "summary": "Inspect evidence paths and confirm the read-only boundary.",
    },
    "basic_disk_triage": {
        "layer": 0,
        "state_key": "raw_triage_findings",
        "mode": "append",
        "summary": "Convert the evidence manifest into a triage-ready placeholder finding.",
    },
    "memory_analysis": {
        "layer": 1,
        "state_key": "memory_findings",
        "mode": "append",
        "summary": "Inspect memory artifacts and capture placeholder live-response findings.",
    },
    "threat_intel_lookup": {
        "layer": 1,
        "state_key": "threat_intel_findings",
        "mode": "append",
        "summary": "Lookup hashes and indicators against threat intelligence sources.",
    },
    "active_vs_dormant_determination": {
        "layer": 1,
        "state_key": "active_vs_dormant_result",
        "mode": "replace",
        "summary": "Determine whether activity appears active now or historical only.",
    },
    "negative_space_reasoning": {
        "layer": 1,
        "state_key": "negative_space_findings",
        "mode": "append",
        "summary": "Note missing artifacts that should exist if the incident behaved normally.",
    },
    "disk_memory_correlation": {
        "layer": 2,
        "state_key": "correlation_results",
        "mode": "append",
        "summary": "Cross-reference disk and memory findings for consistency checks.",
    },
    "mitre_mapping": {
        "layer": 2,
        "state_key": "attack_technique_mappings",
        "mode": "append",
        "summary": "Map confirmed findings to ATT&CK techniques.",
    },
    "evidence_relationship_graph": {
        "layer": 2,
        "state_key": "evidence_relationship_graph",
        "mode": "replace",
        "summary": "Build the causal graph linking artifacts to findings.",
    },
    "confidence_calibration": {
        "layer": 2,
        "state_key": "confidence_scores",
        "mode": "append",
        "summary": "Assign confidence and note uncertainty drivers for each finding.",
    },
    "hypothesis_driven_investigation": {
        "layer": 3,
        "state_key": "hypotheses",
        "mode": "append",
        "summary": "Rank hypotheses and capture placeholder validation plans.",
    },
    "blast_radius_assessment": {
        "layer": 3,
        "state_key": "blast_radius_assessment",
        "mode": "replace",
        "summary": "Estimate whether the compromise is isolated or spreading.",
    },
    "attacker_perspective": {
        "layer": 3,
        "state_key": "attacker_intent_summary",
        "mode": "replace",
        "summary": "Summarize the incident from the attacker's point of view.",
    },
    "predictive_next_step_reasoning": {
        "layer": 3,
        "state_key": "predicted_next_steps",
        "mode": "append",
        "summary": "Predict the likely next attacker move and timing window.",
    },
    "timeline_reconstruction": {
        "layer": 3,
        "state_key": "attack_timeline",
        "mode": "append",
        "summary": "Reconstruct the incident timeline from timestamped evidence.",
    },
    "escalation_decision": {
        "layer": 4,
        "state_key": "escalation_decision",
        "mode": "replace",
        "summary": "Decide whether autonomous handling is enough or a human is needed.",
    },
    "ioc_extraction": {
        "layer": 4,
        "state_key": "iocs",
        "mode": "append",
        "summary": "Package indicators of compromise for downstream sharing.",
    },
    "accuracy_benchmarking": {
        "layer": 4,
        "state_key": "benchmark_results",
        "mode": "replace",
        "summary": "Score the current run against ground-truth expectations.",
    },
    "dual_audience_reporting": {
        "layer": 4,
        "state_key": "final_reports",
        "mode": "append",
        "summary": "Emit parallel analyst and executive report stubs.",
    },
    "remediation_playbook": {
        "layer": 4,
        "state_key": "remediation_steps",
        "mode": "append",
        "summary": "Produce a prioritized response playbook.",
    },
    "self_correction_loop": {
        "layer": 4,
        "state_key": "self_correction_trace",
        "mode": "append",
        "summary": "Record the loop iteration and decide whether another pass is warranted.",
    },
}


def _trace_id(node_name: str, iteration_count: int) -> str:
    return f"{node_name}:{iteration_count + 1}"


def _base_record(node_name: str, state: AgentState, spec: dict[str, Any]) -> dict[str, Any]:
    iteration_count = int(state.get("iteration_count", 0))
    max_iterations = int(state.get("max_iterations", 1))
    retry_requested = bool(state.get("retry_requested", False))

    return {
        "node": node_name,
        "layer": spec["layer"],
        "summary": spec["summary"],
        "status": "placeholder",
        "confidence": 0.0,
        "trace_id": _trace_id(node_name, iteration_count),
        "iteration_count": iteration_count,
        "max_iterations": max_iterations,
        "retry_requested": retry_requested,
        "source_artifacts": list(state.get("evidence_file_paths", [])),
    }


def create_stub_node(node_name: str) -> NodeFunction:
    spec = NODE_DEFINITIONS[node_name]

    def node(state: AgentState) -> dict[str, Any]:
        audit_entry = AUDIT_LOGGER.record(
            node=node_name,
            event="node_executed",
            state=dict(state),
            details={
                "layer": spec["layer"],
                "state_key": spec["state_key"],
                "mode": spec["mode"],
                "summary": spec["summary"],
            },
        )

        record = _base_record(node_name, state, spec)
        output: dict[str, Any] = {"audit_log": [audit_entry]}
        adapter = build_default_adapter()

        if node_name == "evidence_integrity":
            evidence_report = adapter.inspect_manifest(state.get("evidence_file_paths", []))
            output[spec["state_key"]] = {
                **evidence_report,
                "node": node_name,
                "layer": spec["layer"],
                "status": "read_only_boundary_confirmed",
                "summary": spec["summary"],
                "trace_id": record["trace_id"],
            }
            return output

        if node_name == "basic_disk_triage":
            triage_summary = build_disk_triage_summary(state.get("evidence_file_paths", []))
            disk_image_count = triage_summary["disk_image_count"]
            record["status"] = (
                "triage_manifest_ready" if disk_image_count > 0 else "triage_pending_no_disk_image"
            )
            record["confidence"] = 0.2 if disk_image_count > 0 else 0.05
            record["details"] = triage_summary
            output[spec["state_key"]] = [record]
            return output

        if node_name == "evidence_relationship_graph":
            graph = build_evidence_relationship_graph(state)
            output[spec["state_key"]] = {
                **graph,
                "node": node_name,
                "layer": spec["layer"],
                "trace_id": record["trace_id"],
            }
            return output

        if node_name == "confidence_calibration":
            output[spec["state_key"]] = calibrate_confidence_scores(state)
            return output

        if node_name == "hypothesis_driven_investigation":
            output[spec["state_key"]] = rank_hypotheses(state)
            return output

        if node_name == "self_correction_loop":
            iteration_count = int(state.get("iteration_count", 0))
            record["iteration_count_after"] = iteration_count + 1
            output[spec["state_key"]] = [record]
            output["iteration_count"] = iteration_count + 1
            return output

        if spec["mode"] == "append":
            output[spec["state_key"]] = [record]
            return output

        if spec["mode"] == "replace":
            output[spec["state_key"]] = record
            return output

        raise ValueError(f"Unsupported mode for node {node_name!r}: {spec['mode']!r}")

    node.__name__ = node_name
    node.__qualname__ = node_name
    return node


audit_trail = create_stub_node("audit_trail")
evidence_integrity = create_stub_node("evidence_integrity")
basic_disk_triage = create_stub_node("basic_disk_triage")
memory_analysis = create_stub_node("memory_analysis")
threat_intel_lookup = create_stub_node("threat_intel_lookup")
active_vs_dormant_determination = create_stub_node("active_vs_dormant_determination")
negative_space_reasoning = create_stub_node("negative_space_reasoning")
disk_memory_correlation = create_stub_node("disk_memory_correlation")
mitre_mapping = create_stub_node("mitre_mapping")
evidence_relationship_graph = create_stub_node("evidence_relationship_graph")
confidence_calibration = create_stub_node("confidence_calibration")
hypothesis_driven_investigation = create_stub_node("hypothesis_driven_investigation")
blast_radius_assessment = create_stub_node("blast_radius_assessment")
attacker_perspective = create_stub_node("attacker_perspective")
predictive_next_step_reasoning = create_stub_node("predictive_next_step_reasoning")
timeline_reconstruction = create_stub_node("timeline_reconstruction")
escalation_decision = create_stub_node("escalation_decision")
ioc_extraction = create_stub_node("ioc_extraction")
accuracy_benchmarking = create_stub_node("accuracy_benchmarking")
dual_audience_reporting = create_stub_node("dual_audience_reporting")
remediation_playbook = create_stub_node("remediation_playbook")
self_correction_loop = create_stub_node("self_correction_loop")


__all__ = [
    "NODE_DEFINITIONS",
    "accuracy_benchmarking",
    "active_vs_dormant_determination",
    "audit_trail",
    "attacker_perspective",
    "basic_disk_triage",
    "blast_radius_assessment",
    "confidence_calibration",
    "create_stub_node",
    "disk_memory_correlation",
    "dual_audience_reporting",
    "evidence_integrity",
    "evidence_relationship_graph",
    "escalation_decision",
    "hypothesis_driven_investigation",
    "ioc_extraction",
    "memory_analysis",
    "mitre_mapping",
    "negative_space_reasoning",
    "predictive_next_step_reasoning",
    "remediation_playbook",
    "self_correction_loop",
    "threat_intel_lookup",
    "timeline_reconstruction",
]