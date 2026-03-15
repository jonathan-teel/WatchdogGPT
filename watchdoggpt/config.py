from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DEFAULT_OUTPUT_FILENAME = "watchdoggpt_analysis_output.log"
DEFAULT_MODEL = "gpt-5-mini"


class ConfigurationError(ValueError):
    """Raised when the environment configuration is invalid."""


@dataclass(frozen=True, slots=True)
class Settings:
    log_file_path: Path
    output_file_path: Path
    openai_api_key: str | None
    openai_api_model: str
    openai_base_url: str | None
    buffer_flush_interval: float
    buffer_size_limit: int
    chunk_size: int
    max_workers: int
    max_api_calls_per_period: int
    api_rate_limit_period: float
    request_timeout_seconds: float
    max_output_tokens: int
    max_retries: int
    initial_retry_backoff_seconds: float
    alert_webhook_url: str | None
    openai_reasoning_effort: str
    prompt_cache_key: str


def _read_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer.") from exc

    if value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}.")
    return value


def _read_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number.") from exc

    if value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}.")
    return value


def load_settings(output_file_path: str | None = None) -> Settings:
    log_file = os.getenv("LOG_FILE_PATH")
    if not log_file:
        raise ConfigurationError("LOG_FILE_PATH is required.")

    output_path = Path(output_file_path or DEFAULT_OUTPUT_FILENAME).expanduser().resolve()
    reasoning_effort = os.getenv("OPENAI_REASONING_EFFORT", "low").strip().lower() or "low"
    if reasoning_effort not in {"none", "low", "medium", "high"}:
        raise ConfigurationError(
            "OPENAI_REASONING_EFFORT must be one of: none, low, medium, high."
        )

    return Settings(
        log_file_path=Path(log_file).expanduser().resolve(),
        output_file_path=output_path,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        openai_api_model=os.getenv("OPENAI_API_MODEL", DEFAULT_MODEL),
        openai_base_url=os.getenv("OPENAI_BASE_URL"),
        buffer_flush_interval=_read_float("BUFFER_FLUSH_INTERVAL", 15.0, minimum=0.1),
        buffer_size_limit=_read_int("BUFFER_SIZE_LIMIT", 500),
        chunk_size=_read_int("CHUNK_SIZE", 200),
        max_workers=_read_int("MAX_WORKERS", 2),
        max_api_calls_per_period=_read_int("MAX_API_CALLS_PER_PERIOD", 60),
        api_rate_limit_period=_read_float("API_RATE_LIMIT_PERIOD", 60.0, minimum=0.1),
        request_timeout_seconds=_read_float("REQUEST_TIMEOUT_SECONDS", 30.0, minimum=0.1),
        max_output_tokens=_read_int("MAX_OUTPUT_TOKENS", 900),
        max_retries=_read_int("MAX_RETRIES", 3),
        initial_retry_backoff_seconds=_read_float(
            "INITIAL_RETRY_BACKOFF_SECONDS", 1.0, minimum=0.1
        ),
        alert_webhook_url=os.getenv("ALERT_WEBHOOK_URL"),
        openai_reasoning_effort=reasoning_effort,
        prompt_cache_key=os.getenv("PROMPT_CACHE_KEY", "watchdoggpt-analysis-v2"),
    )
