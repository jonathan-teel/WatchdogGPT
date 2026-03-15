from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol, Sequence

from pydantic import BaseModel, Field


class ModelFinding(BaseModel):
    severity: Literal["low", "medium", "high", "critical"] = "low"
    confidence: float = Field(ge=0.0, le=1.0)
    category: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1)
    evidence_lines: list[int] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    dedupe_key: str = ""


class ModelBatchAssessment(BaseModel):
    suspicious: bool = False
    summary: str = ""
    findings: list[ModelFinding] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DetectionFinding:
    severity: str
    confidence: float
    category: str
    summary: str
    evidence_lines: list[int] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    recommended_action: str = ""
    dedupe_key: str = ""


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    entries: list[str]
    suspicious: bool
    summary: str
    findings: list[DetectionFinding]
    model: str
    response_id: str | None = None
    cached_tokens: int | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class PreparedLogEntry:
    line_number: int
    sanitized_text: str
    sequence_keys: tuple[str, ...]
    prompt_injection_signals: tuple[str, ...]
    truncated: bool


class Analyzer(Protocol):
    def analyze_chunk(self, entries: Sequence[str]) -> AnalysisResult:
        ...


class AlertSink(Protocol):
    def emit(self, result: AnalysisResult) -> None:
        ...
