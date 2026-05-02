from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from typing import Any, cast

from .contracts import build_initial_state_payload, validate_initial_state
from .graph import build_graph
from .state import AgentState


def build_initial_state(
    *,
    evidence_file_paths: Sequence[str] | None = None,
    max_iterations: int = 1,
    retry_requested: bool = False,
) -> AgentState:
    state = cast(
        dict[str, Any],
        build_initial_state_payload(
            evidence_file_paths=evidence_file_paths,
            max_iterations=max_iterations,
            retry_requested=retry_requested,
        ),
    )
    validate_initial_state(state)
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