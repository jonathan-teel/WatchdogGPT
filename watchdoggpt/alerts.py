from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import asdict
from typing import Sequence

from watchdoggpt.config import Settings
from watchdoggpt.models import AlertSink, AnalysisResult


class NullAlertSink:
    def emit(self, result: AnalysisResult) -> None:
        return None


class WebhookAlertSink:
    def __init__(self, webhook_url: str, timeout_seconds: float) -> None:
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds

    def emit(self, result: AnalysisResult) -> None:
        payload = json.dumps(
            {
                "model": result.model,
                "summary": result.summary,
                "suspicious": result.suspicious,
                "response_id": result.response_id,
                "findings": [asdict(finding) for finding in result.findings],
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds):
                return None
        except urllib.error.URLError as exc:
            logging.error("Failed to deliver webhook alert: %s", exc)


class CompositeAlertSink:
    def __init__(self, sinks: Sequence[AlertSink]) -> None:
        self.sinks = list(sinks)

    def emit(self, result: AnalysisResult) -> None:
        for sink in self.sinks:
            sink.emit(result)


def build_alert_sink(settings: Settings) -> AlertSink:
    sinks: list[AlertSink] = []
    if settings.alert_webhook_url:
        sinks.append(WebhookAlertSink(settings.alert_webhook_url, settings.request_timeout_seconds))
    if not sinks:
        return NullAlertSink()
    return CompositeAlertSink(sinks)
