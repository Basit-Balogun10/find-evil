from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from unittest import TestCase
from unittest.mock import patch


ROOT_DIRECTORY = Path(__file__).resolve().parents[1]
SRC_DIRECTORY = ROOT_DIRECTORY / "src"
if str(SRC_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SRC_DIRECTORY))

from find_evil.adapters import SiftUnavailableError, UnavailableSiftAdapter
from find_evil.contracts import ContractViolationError, build_initial_state_payload, validate_initial_state, validate_node_output
from find_evil.app import build_initial_state, run_case
from find_evil.audit import AuditLogger
from find_evil.evidence import (
    build_disk_triage_summary,
    build_evidence_integrity_report,
    classify_evidence_path,
)
from find_evil.graph import NODE_SEQUENCE, build_graph, route_after_self_correction
from find_evil.reasoning import calibrate_confidence_scores, build_evidence_relationship_graph, rank_hypotheses
from find_evil.reporting import build_accuracy_benchmark_summary, build_dual_audience_reports, build_remediation_playbook, decide_escalation, extract_iocs
from find_evil import nodes


class FindEvilGraphTests(TestCase):
    def test_build_initial_state_sets_expected_defaults(self) -> None:
        state = build_initial_state(evidence_file_paths=["/cases/disk.dd"], max_iterations=3)

        self.assertEqual(state["evidence_file_paths"], ["/cases/disk.dd"])
        self.assertEqual(state["iteration_count"], 0)
        self.assertEqual(state["max_iterations"], 3)
        self.assertFalse(state["retry_requested"])
        self.assertEqual(state["raw_triage_findings"], [])
        self.assertEqual(state["audit_log"], [])

    def test_route_after_self_correction_stops_without_retry(self) -> None:
        state = build_initial_state(retry_requested=False)

        self.assertEqual(route_after_self_correction(state), "end")

    def test_route_after_self_correction_repeats_when_capacity_remains(self) -> None:
        state = build_initial_state(retry_requested=True, max_iterations=2)
        state["iteration_count"] = 1

        self.assertEqual(route_after_self_correction(state), "repeat")

    def test_build_graph_compiles(self) -> None:
        graph = build_graph()

        self.assertIsNotNone(graph)

    def test_validate_node_output_rejects_unknown_keys(self) -> None:
        with self.assertRaises(ContractViolationError):
            validate_node_output("test_node", {"unknown_key": []})

    def test_validate_initial_state_rejects_missing_keys(self) -> None:
        with self.assertRaises(ContractViolationError):
            validate_initial_state({"evidence_file_paths": []})

    def test_build_initial_state_payload_produces_complete_shape(self) -> None:
        payload = build_initial_state_payload(evidence_file_paths=["/cases/disk.dd"])

        validate_initial_state(payload)
        self.assertEqual(payload["evidence_file_paths"], ["/cases/disk.dd"])
        self.assertEqual(payload["iteration_count"], 0)

    def test_classify_evidence_path_recognizes_common_artifacts(self) -> None:
        self.assertEqual(classify_evidence_path("/cases/sample.dd"), "disk_image")
        self.assertEqual(classify_evidence_path("/cases/memory.mem"), "memory_capture")
        self.assertEqual(classify_evidence_path("/cases/timeline.csv"), "text_artifact")
        self.assertEqual(classify_evidence_path("/cases/unknown.bin"), "unknown")

    def test_evidence_integrity_report_marks_artifacts_read_only(self) -> None:
        report = build_evidence_integrity_report(["/cases/sample.dd", "/cases/memory.mem"])

        self.assertTrue(report["read_only_enforced"])
        self.assertFalse(report["write_operations_supported"])
        self.assertEqual(report["evidence_count"], 2)
        self.assertTrue(all(artifact["read_only"] for artifact in report["artifacts"]))

    def test_disk_triage_summary_groups_artifacts_by_type(self) -> None:
        summary = build_disk_triage_summary(["/cases/sample.dd", "/cases/memory.mem", "/cases/notes.txt"])

        self.assertEqual(summary["disk_image_count"], 1)
        self.assertEqual(summary["memory_capture_count"], 1)
        self.assertEqual(summary["other_artifact_count"], 1)
        self.assertGreaterEqual(len(summary["recommendations"]), 1)

    def test_relationship_graph_connects_findings_to_artifacts(self) -> None:
        state = build_initial_state(evidence_file_paths=["/cases/sample.dd"])
        state["raw_triage_findings"] = cast(
            Any,
            [
                {
                    "node": "basic_disk_triage",
                    "layer": 0,
                    "summary": "Prepared triage manifest",
                    "status": "triage_manifest_ready",
                    "confidence": 0.2,
                    "trace_id": "basic_disk_triage:1",
                    "source_artifacts": ["/cases/sample.dd"],
                }
            ],
        )

        graph = build_evidence_relationship_graph(state)

        self.assertEqual(graph["edge_count"], 1)
        self.assertGreaterEqual(graph["node_count"], 2)
        self.assertEqual(graph["edges"][0]["source"], "/cases/sample.dd")

    def test_confidence_calibration_scores_findings_from_supporting_artifacts(self) -> None:
        state = build_initial_state(evidence_file_paths=["/cases/sample.dd"])
        state["raw_triage_findings"] = cast(
            Any,
            [
                {
                    "node": "basic_disk_triage",
                    "layer": 0,
                    "summary": "Prepared triage manifest",
                    "status": "triage_manifest_ready",
                    "confidence": 0.2,
                    "trace_id": "basic_disk_triage:1",
                    "source_artifacts": ["/cases/sample.dd"],
                }
            ],
        )

        scores = calibrate_confidence_scores(state)

        self.assertEqual(len(scores), 1)
        self.assertGreater(scores[0]["confidence"], 0.0)
        self.assertEqual(scores[0]["evidence_count"], 1)

    def test_hypothesis_ranking_adapts_to_available_evidence(self) -> None:
        hypotheses = rank_hypotheses(build_initial_state(evidence_file_paths=["/cases/sample.dd", "/cases/memory.mem"]))

        self.assertGreaterEqual(len(hypotheses), 2)
        self.assertEqual(hypotheses[0]["priority"], 1)
        self.assertIn("Correlate disk and memory evidence", hypotheses[0]["name"])

    def test_dual_audience_reports_include_technical_and_executive_views(self) -> None:
        state = build_initial_state(evidence_file_paths=["/cases/sample.dd"])
        state["hypotheses"] = cast(Any, rank_hypotheses(state))
        state["confidence_scores"] = calibrate_confidence_scores(state)
        state["evidence_relationship_graph"] = build_evidence_relationship_graph(state)

        reports = build_dual_audience_reports(state)

        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]["audience"], "technical analyst")
        self.assertEqual(reports[1]["audience"], "executive brief")

    def test_remediation_playbook_prioritizes_read_only_evidence_handling(self) -> None:
        steps = build_remediation_playbook(build_initial_state())

        self.assertGreaterEqual(len(steps), 4)
        self.assertIn("Preserve evidence read-only", steps[0]["action"])

    def test_ioc_extraction_returns_candidate_indicators(self) -> None:
        state = build_initial_state(evidence_file_paths=["/cases/sample.dd"])
        state["confidence_scores"] = [
            {
                "node": "basic_disk_triage",
                "trace_id": "basic_disk_triage:1",
                "source_collection": "raw_triage_findings",
                "confidence": 0.8,
                "evidence_count": 1,
                "rationale": ["supported by 1 artifact(s)"],
            }
        ]

        iocs = extract_iocs(state)

        self.assertGreaterEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["ioc_type"], "artifact_path")

    def test_accuracy_benchmark_summary_stays_pending_without_ground_truth(self) -> None:
        summary = build_accuracy_benchmark_summary(build_initial_state(evidence_file_paths=["/cases/sample.dd"]))

        self.assertEqual(summary["status"], "pending_ground_truth")
        self.assertFalse(summary["ground_truth_loaded"])

    def test_escalation_decision_remains_conservative_for_scaffold_output(self) -> None:
        state = build_initial_state(evidence_file_paths=["/cases/sample.dd"])
        state["confidence_scores"] = calibrate_confidence_scores(state)

        decision = decide_escalation(state)

        self.assertFalse(decision["should_escalate"])

    def test_unavailable_adapter_inspects_manifest_without_writing(self) -> None:
        adapter = UnavailableSiftAdapter()

        manifest = adapter.inspect_manifest(["/cases/sample.dd"])

        self.assertTrue(manifest["read_only_enforced"])
        self.assertFalse(manifest["write_operations_supported"])
        self.assertEqual(manifest["adapter"], "UnavailableSiftAdapter")

    def test_unavailable_adapter_rejects_live_sift_operations(self) -> None:
        adapter = UnavailableSiftAdapter()

        with self.assertRaises(SiftUnavailableError):
            adapter.triage_disk_image("/cases/sample.dd")

    def test_run_case_executes_single_pass_with_audit_entries(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            audit_log_path = Path(temporary_directory) / "audit.jsonl"
            temporary_logger = AuditLogger(log_path=audit_log_path)

            with patch.object(nodes, "AUDIT_LOGGER", temporary_logger):
                final_state = run_case(build_initial_state(evidence_file_paths=["/cases/sample.dd"]))

            self.assertEqual(final_state["iteration_count"], 1)
            self.assertEqual(len(final_state["self_correction_trace"]), 1)
            self.assertEqual(len(final_state["audit_log"]), len(NODE_SEQUENCE))
            self.assertEqual(final_state["evidence_integrity_report"]["read_only_enforced"], True)
            self.assertEqual(final_state["raw_triage_findings"][0]["status"], "triage_manifest_ready")
            self.assertGreaterEqual(final_state["evidence_relationship_graph"]["edge_count"], 1)
            self.assertGreaterEqual(len(final_state["confidence_scores"]), 1)
            self.assertGreaterEqual(len(final_state["hypotheses"]), 1)
            self.assertEqual(len(final_state["final_reports"]), 2)
            self.assertGreaterEqual(len(final_state["remediation_steps"],), 4)
            self.assertGreaterEqual(len(final_state["iocs"]), 1)
            self.assertEqual(final_state["benchmark_results"]["status"], "pending_ground_truth")
            self.assertFalse(final_state["escalation_decision"]["should_escalate"])
            self.assertTrue(audit_log_path.exists())
            self.assertEqual(len(audit_log_path.read_text(encoding="utf-8").splitlines()), len(NODE_SEQUENCE))

    def test_run_case_repeats_once_when_retry_is_requested(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            audit_log_path = Path(temporary_directory) / "audit.jsonl"
            temporary_logger = AuditLogger(log_path=audit_log_path)

            with patch.object(nodes, "AUDIT_LOGGER", temporary_logger):
                final_state = run_case(build_initial_state(max_iterations=2, retry_requested=True))

            self.assertEqual(final_state["iteration_count"], 2)
            self.assertEqual(len(final_state["self_correction_trace"]), 2)
            self.assertEqual(len(final_state["audit_log"]), len(NODE_SEQUENCE) * 2)
            self.assertEqual(len(audit_log_path.read_text(encoding="utf-8").splitlines()), len(NODE_SEQUENCE) * 2)