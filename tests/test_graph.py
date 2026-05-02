from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from find_evil.app import build_initial_state, run_case
from find_evil.audit import AuditLogger
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

    def test_run_case_executes_single_pass_with_audit_entries(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            audit_log_path = Path(temporary_directory) / "audit.jsonl"
            temporary_logger = AuditLogger(log_path=audit_log_path)

            with patch.object(nodes, "AUDIT_LOGGER", temporary_logger):
                final_state = run_case(build_initial_state())

            self.assertEqual(final_state["iteration_count"], 1)
            self.assertEqual(len(final_state["self_correction_trace"]), 1)
            self.assertEqual(len(final_state["audit_log"]), len(NODE_SEQUENCE))
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