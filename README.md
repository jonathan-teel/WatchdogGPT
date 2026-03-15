# WatchdogGPT

WatchdogGPT is an open-source Python tool that uses OpenAI GPT models to analyze server logs in real time or historical mode. It detects suspicious activity, identifies potential hacking attempts, and generates concise security reports to help developers and system administrators quickly understand abnormal behavior.

WatchdogGPT demonstrates how large language models can be integrated directly into infrastructure monitoring and security workflows.

## Why WatchdogGPT

Modern infrastructure generates massive volumes of logs. Traditional rule-based monitoring systems can miss subtle attack patterns or unusual sequences of events.

WatchdogGPT applies AI reasoning to log streams, allowing it to:

- detect suspicious behavior patterns
- interpret multi-line attack sequences
- generate human-readable security reports
- surface indicators of compromise for investigation

This makes it useful for developers, DevOps teams, and security researchers experimenting with AI-assisted observability and infrastructure monitoring.

## Use Cases

WatchdogGPT can be used in several real-world infrastructure and security scenarios.

### Security Monitoring

Analyze authentication logs, web server logs, and system events to detect suspicious activity such as brute force attempts, credential stuffing, or unusual access patterns.

### DevOps Observability

Use AI-assisted analysis to interpret noisy log streams and surface meaningful insights from infrastructure events.

### Incident Investigation

Replay historical logs and have the model summarize attack sequences or suspicious behavior during incident response.

### Security Research

Experiment with LLM-based detection of attack patterns across different log formats and environments.

### AI-assisted SOC tooling

Use WatchdogGPT as a base for building lightweight AI-powered monitoring systems or automated security alert pipelines.

## Features

- Real-time log file monitoring using the watchdog library
- Historical replay mode for analyzing an existing log file
- AI-powered log analysis using the OpenAI Python client and Responses API
- Detection of suspicious activity and potential hacking attempts
- Sequence-aware batching that groups related events by IP, session, user, and host before analysis
- Structured model output with severity, confidence, evidence lines, indicators, and recommended actions
- Parallelized chunk analysis using concurrent.futures for improved throughput
- Optional webhook alerts for suspicious findings
- Prompt-cache visibility when cached token usage is returned by the API

## Installation

Clone the repository

```bash
git clone https://github.com/jonathan-teel/WatchdogGPT.git
cd WatchdogGPT
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a .env file in the project root or export environment variables directly.

Set required values

```env
OPENAI_API_KEY=your_api_key
LOG_FILE_PATH=/path/to/log/file
```

Optional settings

```env
OPENAI_API_MODEL=gpt-5-mini
BUFFER_FLUSH_INTERVAL=5
BUFFER_SIZE_LIMIT=100
CHUNK_SIZE=25
MAX_WORKERS=4
```

## Usage

Realtime mode

```bash
python main.py
```

History mode

```bash
python main.py -m history
```

Passing an output file

```bash
python main.py -o output.log
```

The script will start monitoring the specified log file, analyzing new entries, and reporting suspicious activity. The analysis results are written to the console and to a file named watchdoggpt_analysis_output.log by default, or to the file you pass with -o.

To stop the script, press Ctrl+C.

## Customization

You can customize the script by modifying the following parameters:

- OPENAI_API_MODEL – choose the model to use (default gpt-5-mini)
- MAX_OUTPUT_TOKENS – adjust the maximum response size from the model
- MAX_WORKERS – adjust chunk analysis concurrency
- CHUNK_SIZE – adjust maximum grouped chunk size
- BUFFER_FLUSH_INTERVAL – control how often buffered entries flush
- BUFFER_SIZE_LIMIT – control how many entries buffer before flush
- SEQUENCE_GAP_LINES – control how long related sequences stay open
- ALERT_WEBHOOK_URL – send suspicious findings to a webhook
- OPENAI_REASONING_EFFORT – set reasoning effort (none, low, medium, high)

## Supported Models

WatchdogGPT uses the OpenAI Python client and Responses API.

Default model: gpt-5-mini

You can switch models with the OPENAI_API_MODEL environment variable.

Custom OpenAI-compatible endpoints can be configured using OPENAI_BASE_URL.

## Contributing

Contributions are welcome. Feel free to open issues or submit pull requests for detection improvements, new log sources, or performance enhancements.

## License

WatchdogGPT is released under the MIT License. See LICENSE for details.
