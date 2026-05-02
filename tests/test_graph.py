from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from find_evil.adapters import SiftUnavailableError, UnavailableSiftAdapter
from find_evil.app import build_initial_state, run_case
from find_evil.audit import AuditLogger
from find_evil.evidence import (
    build_disk_triage_summary,
    build_evidence_integrity_report,
    classify_evidence_path,
)
from find_evil.graph import NODE_SEQUENCE, build_graph, route_after_self_correction
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