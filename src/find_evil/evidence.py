from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence, TypedDict


class EvidenceBoundaryError(RuntimeError):
    """Raised when a requested evidence operation would violate the read-only boundary."""


class EvidenceArtifact(TypedDict):
    path: str
    basename: str
    suffix: str
    inferred_type: str
    read_only: bool
    warnings: list[str]


class EvidenceIntegrityReport(TypedDict):
    read_only_enforced: bool
    write_operations_supported: bool
    evidence_count: int
    artifacts: list[EvidenceArtifact]
    warnings: list[str]


class DiskTriageSummary(TypedDict):
    evidence_count: int
    disk_image_count: int
    memory_capture_count: int
    other_artifact_count: int
    artifacts: list[EvidenceArtifact]
    recommendations: list[str]


DISK_IMAGE_SUFFIXES = {".dd", ".e01", ".img", ".raw", ".vhd", ".vmdk"}
MEMORY_CAPTURE_SUFFIXES = {".dmp", ".dump", ".mem", ".vmem"}
TEXT_ARTIFACT_SUFFIXES = {".csv", ".json", ".log", ".txt", ".xml", ".yaml", ".yml"}


def classify_evidence_path(path: str) -> str:
    suffix = Path(path).suffix.lower()

    if suffix in DISK_IMAGE_SUFFIXES:
        return "disk_image"

    if suffix in MEMORY_CAPTURE_SUFFIXES:
        return "memory_capture"

    if suffix in TEXT_ARTIFACT_SUFFIXES:
        return "text_artifact"

    return "unknown"


def _build_artifact_entry(path: str) -> EvidenceArtifact:
    inferred_type = classify_evidence_path(path)
    warnings: list[str] = []

    if inferred_type == "unknown":
        warnings.append("Artifact type is not recognized yet; defer to a SIFT adapter later.")

    return {
        "path": path,
        "basename": Path(path).name,
        "suffix": Path(path).suffix.lower(),
        "inferred_type": inferred_type,
        "read_only": True,
        "warnings": warnings,
    }


def build_evidence_integrity_report(evidence_file_paths: Sequence[str]) -> EvidenceIntegrityReport:
    artifacts = [_build_artifact_entry(path) for path in evidence_file_paths]
    warnings: list[str] = []

    if not artifacts:
        warnings.append("No evidence paths were supplied; the agent cannot read or modify anything yet.")

    return {
        "read_only_enforced": True,
        "write_operations_supported": False,
        "evidence_count": len(artifacts),
        "artifacts": artifacts,
        "warnings": warnings,
    }


def build_disk_triage_summary(evidence_file_paths: Sequence[str]) -> DiskTriageSummary:
    artifacts = [_build_artifact_entry(path) for path in evidence_file_paths]
    disk_image_count = sum(1 for artifact in artifacts if artifact["inferred_type"] == "disk_image")
    memory_capture_count = sum(1 for artifact in artifacts if artifact["inferred_type"] == "memory_capture")
    other_artifact_count = len(artifacts) - disk_image_count - memory_capture_count
    recommendations: list[str] = []

    if disk_image_count == 0:
        recommendations.append("No disk image path supplied yet; triage remains a manifest-only placeholder.")
    else:
        recommendations.append("Keep evidence read-only and defer content extraction to the SIFT adapter layer.")

    if memory_capture_count == 0:
        recommendations.append("No memory capture path supplied yet; memory analysis will remain stubbed.")

    return {
        "evidence_count": len(artifacts),
        "disk_image_count": disk_image_count,
        "memory_capture_count": memory_capture_count,
        "other_artifact_count": other_artifact_count,
        "artifacts": artifacts,
        "recommendations": recommendations,
    }


@dataclass(slots=True)
class ReadOnlyEvidenceStore:
    root: Path

    def _resolve(self, evidence_path: str) -> Path:
        candidate = Path(evidence_path)

        if not candidate.is_absolute():
            candidate = (self.root / candidate).resolve(strict=False)
        else:
            candidate = candidate.resolve(strict=False)

        root_path = self.root.resolve(strict=False)
        if root_path not in candidate.parents and candidate != root_path:
            raise EvidenceBoundaryError(f"Evidence path {candidate} is outside read-only root {root_path}.")

        return candidate

    def read_bytes(self, evidence_path: str) -> bytes:
        resolved_path = self._resolve(evidence_path)
        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        return resolved_path.read_bytes()

    def read_text(self, evidence_path: str, encoding: str = "utf-8") -> str:
        return self.read_bytes(evidence_path).decode(encoding)