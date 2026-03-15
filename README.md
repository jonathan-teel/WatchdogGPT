# WatchdogGPT

WatchdogGPT monitors a server log file, batches new entries safely, and uses an LLM to flag suspicious activity in near real time.

## What Changed

- Tracks file offsets instead of rereading the last line, so appended bursts are not dropped.
- Handles partial writes, truncation, and log rotation.
- Uses the modern OpenAI Python client with Responses API structured outputs.
- Groups related entries by recurring actor/session/request indicators before analysis.
- Hardens the prompt boundary by serializing log lines as JSON and flagging prompt-like payloads as hostile data.
- Replaces the broken timer/thread-pool design with a single buffered flush loop.
- Supports optional webhook alerts for suspicious batches.

## Requirements

- Python 3.11+
- An OpenAI API key

## Installation

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Copy the example environment file and update it:

   ```bash
   cp ./watchdoggpt/.env.example ./watchdoggpt/.env
   ```

3. Set at minimum:

   - `LOG_FILE_PATH`
   - `OPENAI_API_KEY`
   - `OPENAI_API_MODEL`

## Usage

Realtime mode:

```bash
python main.py
```

History mode:

```bash
python main.py --mode history
```

Custom output log:

```bash
python main.py --output output.log
```

## Key Environment Variables

- `LOG_FILE_PATH`: log file to monitor or replay.
- `OPENAI_API_MODEL`: defaults to `gpt-5-mini`.
- `BUFFER_FLUSH_INTERVAL`: seconds between scheduled flushes.
- `BUFFER_SIZE_LIMIT`: flush immediately when the in-memory buffer reaches this many lines.
- `CHUNK_SIZE`: max lines per LLM request.
- `SEQUENCE_GAP_LINES`: max line distance for continuing the same inferred event sequence.
- `MAX_WORKERS`: number of chunk analyses to run in parallel during a flush.
- `MAX_ENTRY_CHARACTERS`: per-line character cap before truncation markers are applied.
- `ALERT_WEBHOOK_URL`: optional webhook that receives suspicious findings as JSON.

## Notes

- The log file contents are treated as untrusted input in the model prompt.
- Embedded strings such as `ignore previous instructions` are annotated as hostile log content, not followed.
- History mode and realtime mode both flow through the same `process_entries -> flush_now -> analyze` pipeline.
- Alerts are logged to stdout and the output file; webhook delivery is optional.

## Testing

```bash
python -m unittest discover -s tests -v
```

## License

WatchdogGPT is released under the MIT License. See [LICENSE](./LICENSE) for details.
