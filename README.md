# WatchdogGPT

WatchdogGPT is a Python script that utilizes OpenAI's GPT models to monitor and analyze server access logs in real-time. It detects suspicious activity and potential hacking attempts, providing a concise report for further inspection. Supports two logging formats - CLF and ELFF

## Features

- Real-time log file monitoring using the watchdog library
- Analysis of log entries using OpenAI's GPT models or llama 
- Detection of suspicious activity and potential hacking attempts
- Parallelized log entry analysis using concurrent.futures library for improved performance and concurrency
- Parallelized api calls (be careful of cost)

## Installation

1. Clone the repository via `git clone https://github.com/yourusername/WatchdogGPT.git` and `cd` into the cloned repository.
2. Install the required packages: `pip install -r requirements.txt`
3. Copy the .env.example file to .env: `cp .env.example .env`. This is where you will set the following variables:
4. Set your OpenAI API values in the OPENAI_API_KEY, OPENAPI_API_MODEL variables.
5. Set your log file information in LOG_FILE_PATH and LOG_FILE_FORMAT
6. Set your timing/capacity for api calls in BUFFER_FLUSH_INTERVAL and BUFFER_SIZE_LIMIT (Default 60 and 1000)
7. Run the script.

## Usage

Run the script:

Realtime mode - 
python watchdoggpt.py

History mode -
python watchdoggpt.py -m history

The script will start monitoring the specified log file, analyzing any new entries, and reporting suspicious activities. The analysis results will be printed to the console and written to a file named watchdoggpt_analysis.log in the same directory.

To stop the script, press Ctrl+C.

## Customization

You can customize the script by modifying the following parameters:

- MAX_TOKENS: Adjust the maximum number of tokens to send to the GPT model
- send_alert(): Implement your preferred alerting mechanism (e.g., email, Slack)
- MAX_WORKERS: Adjust for desired level of concurrency
- CHUNK_SIZE: Adjust for granularity of buffer chunks

## Supported Models<a name="supported-models"></a>

This script works with all OpenAI models, as well as Llama through Llama.cpp. Default model is **gpt-3.5-turbo**. To use a different model, specify it through OPENAI_API_MODEL.

### Llama

Download the latest version of [Llama.cpp](https://github.com/ggerganov/llama.cpp) and follow instructions to make it. You will also need the Llama model weights.

After that link `llama/main` to llama.cpp/main and `models` to the folder where you have the Llama model weights. Then run the script with `OPENAI_API_MODEL=llama`.

## Contributing

Contributions are welcome, please feel free to submit a pull request or create an issue for any bugs or feature requests.

## License

WatchdogGPT is released under the MIT License. See LICENSE for details.