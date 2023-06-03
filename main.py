#!/usr/bin/env python3
import os
import logging
import threading
from watchdog.observers import Observer
import argparse
from watchdoggpt.core import WatchdogGPT
from watchdoggpt.logging import setup_logging
from watchdoggpt.config import LOG_FILE_PATH

def main():
    parser = argparse.ArgumentParser(description="WatchdogGPT: Log analysis using GPT.")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["realtime", "history"],
        default="realtime",
        help="Choose the mode of operation: realtime (default) or history.",
    )
    parser.add_argument(
        "-l",
        "--log",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'watchdoggpt_analysis.log'),
        help="Path to the log file.",
    )
    args = parser.parse_args()

    setup_logging(args.log)

    wdgpt = WatchdogGPT()
    if args.mode == "realtime":
        observer = Observer()
        observer.schedule(wdgpt, path=os.path.dirname(LOG_FILE_PATH), recursive=False)
        observer.start()
        try:
            stop_event = threading.Event()
            while not stop_event.is_set():
                stop_event.wait(1)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()
    elif args.mode == "history":
        with open(LOG_FILE_PATH, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line:
                    wdgpt.buffered_entries.append(line)
                    wdgpt.token_count += len(line.split())
        wdgpt.flush_buffer()

if __name__ == '__main__':
    main()
