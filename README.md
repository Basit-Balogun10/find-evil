# Find Evil

LangGraph scaffold for the SANS Find Evil hackathon.

This repository is intentionally small right now: the SIFT Workstation is not installed yet, so the graph is built as a fully wired shell with stubbed analysis nodes, typed shared state, and a JSONL audit trail. The code is structured so real forensic tool calls can be dropped into the node stubs later without changing the overall graph shape.

## What Is Here

- `find_evil/state.py` defines the shared `AgentState`.
- `find_evil/audit.py` writes structured audit entries to `logs/audit.jsonl`.
- `find_evil/nodes.py` contains stub implementations for all 22 analysis stages.
- `find_evil/graph.py` wires the nodes together in LangGraph.
- `find_evil/app.py` builds the initial state and runs the graph.
- `main.py` is the CLI entrypoint.

## Why `find_evil`

The repository stays named `find-evil` because that is the project name on disk and on GitHub. The Python package is `find_evil` because hyphens are not valid in Python import names, so the importable module uses underscores while the repo keeps the human-readable hyphenated name.

## Run

```bash
uv run python main.py
```

Optional flags:

- `--evidence PATH` may be repeated to seed evidence file paths.
- `--max-iterations N` sets the self-correction cap.
- `--retry-requested` seeds the loop to repeat when the cap allows it.

## Safety Boundary

The current scaffold does not touch evidence files. That constraint will be enforced architecturally when SIFT tool calls are added.
