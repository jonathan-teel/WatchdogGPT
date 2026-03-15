#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time

from watchdog.observers import Observer

from watchdoggpt.config import DEFAULT_OUTPUT_FILENAME, ConfigurationError, load_settings
from watchdoggpt.core import WatchdogGPT
from watchdoggpt.logging import setup_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WatchdogGPT: real-time log analysis with LLMs.")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["realtime", "history"],
        default="realtime",
        help="Choose the mode of operation: realtime (default) or history.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_FILENAME,
        help="Path to the analysis output log file.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        settings = load_settings(output_file_path=args.output)
    except ConfigurationError as exc:
        raise SystemExit(str(exc)) from exc

    setup_logging(settings.output_file_path)
    try:
        watchdog = WatchdogGPT(settings, follow_from_end=args.mode == "realtime")
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.mode == "history":
        try:
            watchdog.process_history()
        finally:
            watchdog.close()
        return

    observer = Observer()
    observer.schedule(watchdog, path=str(settings.log_file_path.parent), recursive=False)
    watchdog.start()
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        watchdog.close()


if __name__ == "__main__":
    main()
