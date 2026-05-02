from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence, runtime_checkable

from .evidence import build_evidence_integrity_report


class SiftUnavailableError(RuntimeError):
    """Raised when a SIFT-backed operation is requested before the workstation is available."""


@runtime_checkable
class IncidentResponseAdapter(Protocol):
    def inspect_manifest(self, evidence_file_paths: Sequence[str]) -> dict[str, Any]:
        ...

    def triage_disk_image(self, evidence_path: str) -> dict[str, Any]:
        ...

    def analyze_memory_capture(self, evidence_path: str) -> dict[str, Any]:
        ...

    def lookup_threat_intel(self, indicators: Sequence[str]) -> dict[str, Any]:
        ...

    def extract_iocs(self, findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        ...


@dataclass(slots=True)
class UnavailableSiftAdapter:
    reason: str = "SIFT Workstation is not installed yet."

    def inspect_manifest(self, evidence_file_paths: Sequence[str]) -> dict[str, Any]:
        return {
            **build_evidence_integrity_report(evidence_file_paths),
            "adapter": self.__class__.__name__,
            "reason": self.reason,
        }

    def triage_disk_image(self, evidence_path: str) -> dict[str, Any]:
        raise SiftUnavailableError(
            f"Disk triage for {evidence_path!r} is unavailable until SIFT is connected: {self.reason}"
        )

    def analyze_memory_capture(self, evidence_path: str) -> dict[str, Any]:
        raise SiftUnavailableError(
            f"Memory analysis for {evidence_path!r} is unavailable until SIFT is connected: {self.reason}"
        )

    def lookup_threat_intel(self, indicators: Sequence[str]) -> dict[str, Any]:
        raise SiftUnavailableError(
            f"Threat-intelligence lookup is unavailable until SIFT is connected: {self.reason}"
        )

    def extract_iocs(self, findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        raise SiftUnavailableError(
            f"IOC extraction is unavailable until SIFT is connected: {self.reason}"
        )


def build_default_adapter() -> IncidentResponseAdapter:
    return UnavailableSiftAdapter()