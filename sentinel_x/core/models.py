"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
CONFIDENCES = ["Insufficient Evidence", "Low Confidence", "Medium Confidence", "High Confidence"]
CLASSIFICATIONS = ["Observed", "Inferred", "Unknown"]


@dataclass
class LogEvent:
    evidence_id: str
    file: str
    line: int
    ip: str
    ts: datetime
    method: str
    path: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw: str


@dataclass
class Finding:
    id: str
    type: str
    timestamp: datetime
    evidence_id: str
    file: str
    line: int | None
    ip: str
    severity: str
    confidence: str
    classification: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "evidence_id": self.evidence_id,
            "file": self.file,
            "line": self.line,
            "ip": self.ip,
            "severity": self.severity,
            "confidence": self.confidence,
            "classification": self.classification,
            "description": self.description,
            "details": self.details,
        }


@dataclass
class AuthEvent:
    """One SSH authentication event parsed from auth.log / secure / journald export."""
    evidence_id: str
    file: str
    line: int
    ts: datetime
    host: str
    kind: str          # failed | accepted | invalid_user
    user: str
    ip: str
    method: str
    invalid_user: bool
    raw: str
