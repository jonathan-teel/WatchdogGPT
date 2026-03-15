# WatchdogGPT

WatchdogGPT is a Python script that utilizes OpenAI's GPT models to monitor and analyze logs in real-time or historical mode. It detects suspicious activity and potential hacking attempts, providing a concise report for further inspection.

## Features

- Real-time log file monitoring using the `watchdog` library
- Historical replay mode for analyzing an existing log file
- Analysis of log entries using the OpenAI Python client and Responses API
- Detection of suspicious activity and potential hacking attempts
- Sequence-aware batching that groups related events by IP, session, user, and host before analysis
- Structured model output with severity, confidence, evidence lines, indicators, and recommended actions
- Parallelized chunk analysis using `concurrent.futures` for improved throughput
- Optional webhook alerts for suspicious findings
- Prompt-cache visibility when cached token usage is returned by the API

## Installation

1. Clone the repository.
2. Install the required packages: `pip install -r requirements.txt`
3. Create a `.env` file in the project root or export the environment variables directly.
4. Set your OpenAI API values in `OPENAI_API_KEY` and optionally `OPENAI_API_MODEL`.
5. Set your log file information in `LOG_FILE_PATH`.
6. Set your timing and capacity values such as `BUFFER_FLUSH_INTERVAL`, `BUFFER_SIZE_LIMIT`, `CHUNK_SIZE`, and `MAX_WORKERS`.
7. Run the script.

## Usage

Run the script:

Realtime mode: `python main.py`

History mode: `python main.py -m history`

Passing an output file: `python main.py -o output.log`

The script will start monitoring the specified log file, analyzing new entries, and reporting suspicious activity. The analysis results are written to the console and to a file named `watchdoggpt_analysis_output.log` by default, or to the file you pass with `-o`.

To stop the script, press `Ctrl+C`.

## Customization

You can customize the script by modifying the following parameters:

- `OPENAI_API_MODEL`: choose the model to use, defaults to `gpt-5-mini`
- `MAX_OUTPUT_TOKENS`: adjust the maximum response size from the model
- `MAX_WORKERS`: adjust the level of chunk analysis concurrency
- `CHUNK_SIZE`: adjust the maximum size of a grouped chunk
- `BUFFER_FLUSH_INTERVAL`: control how often buffered entries are flushed
- `BUFFER_SIZE_LIMIT`: control how many entries are buffered before an immediate flush
- `SEQUENCE_GAP_LINES`: control how long related sequences stay open
- `ALERT_WEBHOOK_URL`: send suspicious findings to a webhook
- `OPENAI_REASONING_EFFORT`: set model reasoning effort to `none`, `low`, `medium`, or `high`

## Supported Models

WatchdogGPT uses the current OpenAI Python client and Responses API. By default it uses `gpt-5-mini`, and you can switch models with `OPENAI_API_MODEL`.

If you need a compatible OpenAI-style endpoint, set `OPENAI_BASE_URL` accordingly.

## Contributing

Contributions are welcome. Please feel free to submit a pull request or create an issue for bugs, detection gaps, or feature requests.

## License

WatchdogGPT is released under the MIT License. See `LICENSE` for details.
