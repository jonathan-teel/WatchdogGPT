from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Sequence

from watchdog.events import FileMovedEvent, FileSystemEvent, FileSystemEventHandler

from watchdoggpt.alerts import build_alert_sink
from watchdoggpt.analyzers import OpenAIAnalyzer
from watchdoggpt.config import Settings
from watchdoggpt.log_processing import LogTailer, SequenceAwareChunker
from watchdoggpt.models import AlertSink, AnalysisResult, Analyzer


class WatchdogGPT(FileSystemEventHandler):
    def __init__(
        self,
        settings: Settings,
        *,
        analyzer: Analyzer | None = None,
        alert_sink: AlertSink | None = None,
        follow_from_end: bool = True,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.analyzer = analyzer or OpenAIAnalyzer(settings)
        self.alert_sink = alert_sink or build_alert_sink(settings)
        self.tailer = LogTailer(settings.log_file_path, start_at_end=follow_from_end)
        self.chunker = SequenceAwareChunker(
            chunk_size=settings.chunk_size,
            sequence_gap_lines=settings.sequence_gap_lines,
        )
        self._buffer: list[str] = []
        self._buffer_lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._flush_event = threading.Event()
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._flush_loop,
            name="watchdoggpt-flusher",
            daemon=True,
        )
        self._worker_started = False
        self._executor = ThreadPoolExecutor(max_workers=settings.max_workers)
        self._resolved_log_path = settings.log_file_path.resolve(strict=False)

    def start(self) -> None:
        if self._worker_started:
            return

        self._worker_started = True
        self._worker_thread.start()
        logging.info("WatchdogGPT started for %s", self.settings.log_file_path)

    def close(self) -> None:
        self._stop_event.set()
        self._flush_event.set()
        if self._worker_started:
            self._worker_thread.join(timeout=self.settings.buffer_flush_interval + 2.0)
        self.flush_now()
        self._executor.shutdown(wait=True)
        logging.info("WatchdogGPT stopped")

    def on_modified(self, event: FileSystemEvent) -> None:
        if self._is_target_event(event):
            self.process_log_update()

    def on_created(self, event: FileSystemEvent) -> None:
        if self._is_target_event(event):
            self.process_log_update()

    def on_moved(self, event: FileMovedEvent) -> None:
        destination_path = Path(event.dest_path).resolve(strict=False)
        if destination_path == self._resolved_log_path or self._is_target_event(event):
            self.process_log_update()

    def process_log_update(self) -> None:
        self.process_entries(self.tailer.read_new_entries())

    def process_history(self) -> list[AnalysisResult]:
        return self.process_entries(self.tailer.read_all_entries(), flush=True)

    def process_entries(
        self,
        entries: Sequence[str],
        *,
        flush: bool = False,
    ) -> list[AnalysisResult]:
        self.enqueue_entries(entries)
        if flush:
            return self.flush_now()
        return []

    def enqueue_entries(self, entries: Sequence[str]) -> None:
        normalized_entries = [entry for entry in entries if entry and entry.strip()]
        if not normalized_entries:
            return

        with self._buffer_lock:
            self._buffer.extend(normalized_entries)
            should_flush = self._buffer_reached_flush_limit()

        if should_flush:
            self._request_flush()

    def flush_now(self) -> list[AnalysisResult]:
        with self._flush_lock:
            entries = self._take_buffered_entries()
            if not entries:
                return []

            chunks = self._split_into_chunks(entries)
            results = self._analyze_chunks(chunks)
            self._handle_results(results)
            return results

    def _flush_loop(self) -> None:
        while True:
            self._flush_event.wait(self.settings.buffer_flush_interval)
            self._flush_event.clear()
            self.flush_now()
            if self._stop_event.is_set():
                break

    def _analyze_chunks(self, chunks: Sequence[Sequence[str]]) -> list[AnalysisResult]:
        if len(chunks) == 1 or self.settings.max_workers == 1:
            return [self._safe_analyze_chunk(chunk) for chunk in chunks]

        futures = {
            self._executor.submit(self._safe_analyze_chunk, chunk): index
            for index, chunk in enumerate(chunks)
        }
        ordered_results: list[AnalysisResult | None] = [None] * len(chunks)

        for future in as_completed(futures):
            index = futures[future]
            ordered_results[index] = future.result()

        return [result for result in ordered_results if result is not None]

    def _safe_analyze_chunk(self, chunk: Sequence[str]) -> AnalysisResult:
        try:
            return self.analyzer.analyze_chunk(chunk)
        except Exception as exc:  # pragma: no cover - defensive guardrail
            logging.exception("Unhandled analyzer error")
            return AnalysisResult(
                entries=list(chunk),
                suspicious=False,
                summary="Unhandled analyzer exception.",
                findings=[],
                model=self.settings.openai_api_model,
                error=str(exc),
            )

    def _log_result(self, result: AnalysisResult) -> None:
        logging.info("-" * 80)
        logging.info(
            "Analyzed %s lines with %s%s",
            len(result.entries),
            result.model,
            f" (response_id={result.response_id})" if result.response_id else "",
        )
        if result.cached_tokens is not None:
            logging.info("Prompt cache hit tokens: %s", result.cached_tokens)

        if result.error:
            logging.error("Analysis failed: %s", result.error)
            logging.info("-" * 80)
            return

        logging.info("Suspicious: %s", result.suspicious)
        logging.info("Summary: %s", result.summary or "No suspicious activity detected.")

        for finding in result.findings:
            logging.warning(
                "Finding severity=%s confidence=%.2f category=%s summary=%s evidence_lines=%s dedupe_key=%s",
                finding.severity,
                finding.confidence,
                finding.category,
                finding.summary,
                finding.evidence_lines,
                finding.dedupe_key or "n/a",
            )

        logging.info("-" * 80)

    def _take_buffered_entries(self) -> list[str]:
        with self._buffer_lock:
            if not self._buffer:
                return []
            entries = self._buffer
            self._buffer = []
            return entries

    def _buffer_reached_flush_limit(self) -> bool:
        return len(self._buffer) >= self.settings.buffer_size_limit

    def _request_flush(self) -> None:
        self._flush_event.set()

    def _handle_results(self, results: Sequence[AnalysisResult]) -> None:
        for result in results:
            self._log_result(result)
            if self._should_emit_alert(result):
                self.alert_sink.emit(result)

    @staticmethod
    def _should_emit_alert(result: AnalysisResult) -> bool:
        return result.suspicious and bool(result.findings) and result.error is None

    def _is_target_event(self, event: FileSystemEvent) -> bool:
        if event.is_directory:
            return False
        return Path(event.src_path).resolve(strict=False) == self._resolved_log_path

    def _split_into_chunks(self, entries: Sequence[str]) -> list[list[str]]:
        return self.chunker.chunk(entries)
