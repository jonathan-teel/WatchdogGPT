from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from watchdoggpt.models import PreparedLogEntry

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SESSION_RE = re.compile(
    r"\b(?:session(?:id)?|sid|trace(?:id)?|request(?:id)?|req(?:id)?)\s*[=:]\s*([^\s,;]+)",
    re.IGNORECASE,
)
USER_RE = re.compile(
    r"\b(?:user(?:name)?|account|principal|uid)\s*[=:]\s*([^\s,;]+)",
    re.IGNORECASE,
)
HOST_RE = re.compile(r"\b(?:host|hostname|server)\s*[=:]\s*([^\s,;]+)", re.IGNORECASE)
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|bypass)\b.{0,48}\b(?:previous|above|prior|system|developer|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_reference",
        re.compile(
            r"\b(?:system prompt|developer message|assistant message|tool call|function call)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command_request",
        re.compile(
            r"\b(?:run|execute|eval|invoke)\b.{0,24}\b(?:command|script|tool|shell|powershell|bash)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "secret_request",
        re.compile(
            r"\b(?:reveal|print|output exactly|dump)\b.{0,32}\b(?:prompt|secret|token|api[_ -]?key|credential)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter_token",
        re.compile(
            r"```|<\|im_start\|>|<\|assistant\|>|<instruction>|BEGIN PROMPT|END PROMPT",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(slots=True)
class SequenceGroup:
    entries: list[str]
    last_line_index: int
    sequence_keys: set[str] = field(default_factory=set)


class SequenceAwareChunker:
    def __init__(self, chunk_size: int, sequence_gap_lines: int) -> None:
        self.chunk_size = chunk_size
        self.sequence_gap_lines = sequence_gap_lines

    def chunk(self, entries: Sequence[str]) -> list[list[str]]:
        if not entries:
            return []

        groups: list[SequenceGroup] = []
        key_to_group: dict[str, int] = {}

        for line_index, entry in enumerate(entries):
            sequence_keys = extract_sequence_keys(entry)
            group_index = self._select_group(
                groups=groups,
                key_to_group=key_to_group,
                sequence_keys=sequence_keys,
                line_index=line_index,
            )

            if group_index is None:
                groups.append(SequenceGroup(entries=[], last_line_index=line_index))
                group_index = len(groups) - 1

            group = groups[group_index]
            group.entries.append(entry)
            group.last_line_index = line_index
            group.sequence_keys.update(sequence_keys)

            for key in sequence_keys:
                key_to_group[key] = group_index

        return [group.entries for group in groups if group.entries]

    def _select_group(
        self,
        *,
        groups: Sequence[SequenceGroup],
        key_to_group: dict[str, int],
        sequence_keys: Sequence[str],
        line_index: int,
    ) -> int | None:
        candidates: list[int] = []
        for key in sequence_keys:
            group_index = key_to_group.get(key)
            if group_index is None:
                continue
            if self._is_reusable(groups[group_index], line_index):
                candidates.append(group_index)

        if candidates:
            return max(set(candidates), key=lambda index: groups[index].last_line_index)

        if not sequence_keys and groups:
            last_group_index = len(groups) - 1
            if self._is_reusable(groups[last_group_index], line_index):
                return last_group_index

        return None

    def _is_reusable(self, group: SequenceGroup, line_index: int) -> bool:
        return (
            len(group.entries) < self.chunk_size
            and line_index - group.last_line_index <= self.sequence_gap_lines
        )


class LogTailer:
    def __init__(self, log_file_path: Path, *, start_at_end: bool) -> None:
        self.log_file_path = log_file_path
        self._offset = 0
        self._partial_line = ""
        self._signature: tuple[int, int] | None = None

        if start_at_end and log_file_path.exists():
            stat = log_file_path.stat()
            self._signature = self._file_signature(stat)
            self._offset = stat.st_size

    def read_new_entries(self) -> list[str]:
        if not self.log_file_path.exists():
            return []

        stat = self.log_file_path.stat()
        current_signature = self._file_signature(stat)

        if self._signature is None:
            self._signature = current_signature
        elif current_signature != self._signature or stat.st_size < self._offset:
            self._signature = current_signature
            self._offset = 0
            self._partial_line = ""

        with self.log_file_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._offset)
            payload = handle.read()
            self._offset = handle.tell()

        if not payload:
            return []

        combined = f"{self._partial_line}{payload}"
        entries, partial_line = self._split_entries(combined, include_partial=False)
        self._partial_line = partial_line
        return entries

    def read_all_entries(self) -> list[str]:
        if not self.log_file_path.exists():
            return []

        with self.log_file_path.open("r", encoding="utf-8", errors="replace") as handle:
            payload = handle.read()

        entries, partial_line = self._split_entries(payload, include_partial=True)
        if partial_line:
            entries.append(partial_line)
        return entries

    @staticmethod
    def _file_signature(stat_result: object) -> tuple[int, int]:
        stat = stat_result
        return (getattr(stat, "st_dev", 0), getattr(stat, "st_ino", 0))

    @staticmethod
    def _split_entries(payload: str, *, include_partial: bool) -> tuple[list[str], str]:
        lines = payload.splitlines(keepends=True)
        partial_line = ""

        if lines and not lines[-1].endswith(("\n", "\r")):
            partial_line = lines.pop()

        entries = [line.rstrip("\r\n") for line in lines if line.rstrip("\r\n")]
        if include_partial and partial_line:
            entries.append(partial_line)
            partial_line = ""
        return entries, partial_line


def prepare_log_entry(
    *,
    line_number: int,
    entry: str,
    max_entry_characters: int,
) -> PreparedLogEntry:
    sanitized_text, truncated = sanitize_log_entry(entry, max_entry_characters=max_entry_characters)
    return PreparedLogEntry(
        line_number=line_number,
        sanitized_text=sanitized_text,
        sequence_keys=extract_sequence_keys(entry),
        prompt_injection_signals=detect_prompt_injection_signals(entry),
        truncated=truncated,
    )


def sanitize_log_entry(entry: str, *, max_entry_characters: int) -> tuple[str, bool]:
    normalized = entry.replace("\r", "\\r").replace("\n", "\\n")
    sanitized = CONTROL_CHARACTER_RE.sub(_replace_control_character, normalized)
    if len(sanitized) <= max_entry_characters:
        return sanitized, False

    marker = "...[truncated]"
    if max_entry_characters <= len(marker):
        return marker[:max_entry_characters], True
    return sanitized[: max_entry_characters - len(marker)] + marker, True


def extract_sequence_keys(entry: str) -> tuple[str, ...]:
    keys: list[str] = []

    for ip_address in IPV4_RE.findall(entry):
        keys.append(f"ip:{ip_address}")

    for label, pattern in (
        ("session", SESSION_RE),
        ("user", USER_RE),
        ("host", HOST_RE),
    ):
        for match in pattern.findall(entry):
            cleaned = match.strip("\"'[](){}").lower()
            if cleaned:
                keys.append(f"{label}:{cleaned}")

    seen: set[str] = set()
    ordered_keys: list[str] = []
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        ordered_keys.append(key)

    return tuple(ordered_keys[:8])


def detect_prompt_injection_signals(entry: str) -> tuple[str, ...]:
    detected_signals = [
        label for label, pattern in PROMPT_INJECTION_PATTERNS if pattern.search(entry)
    ]
    return tuple(detected_signals)


def _replace_control_character(match: re.Match[str]) -> str:
    character = match.group(0)
    return f"\\u{ord(character):04x}"
