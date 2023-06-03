#!/usr/bin/env python3
import os
import re
import time
import logging
import threading
import openai
import concurrent.futures
from ratelimiter import RateLimiter
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from watchdoggpt.config import LOG_FILE_PATH, OPENAI_API_KEY, OPENAI_API_MODEL, BUFFER_FLUSH_INTERVAL, BUFFER_SIZE_LIMIT, MAX_WORKERS, CHUNK_SIZE

class WatchdogGPT(FileSystemEventHandler):

    def __init__(self):
        self.buffered_entries = []
        self.token_count = 0
        self.print_to_cli("Info:", "Starting WatchdogGPT")
        self.buffer_flush_timer = threading.Timer(BUFFER_FLUSH_INTERVAL, self.flush_buffer)
        self.buffer_flush_timer.start()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) 
        self.rate_limiter = RateLimiter(max_calls=60, period=60)  # Adjust these values based on your OpenAI API rate limit

    def on_modified(self, event):
        if not event.is_directory and event.src_path == LOG_FILE_PATH:
            self.process_log_update()

    def process_log_update(self):
        new_entries = self.read_buffered_log_entries()

        for entry in new_entries:
            if entry:
                entry_tokens = len(entry.split())

                if len(self.buffered_entries) >= BUFFER_SIZE_LIMIT:
                    self.flush_buffer()
                else:
                    self.buffered_entries.append(entry)
                    self.token_count += entry_tokens
            else:
                logging.warning(f"Failed to preprocess log entry: {entry.strip()}")

    def read_buffered_log_entries(self):
        new_entries = []

        with open(LOG_FILE_PATH, 'r') as f:
            lines = f.readlines()

            if lines:
                new_entries = lines[-1:]  # Adjust this value to read more lines per update

        return new_entries

    def analyze(self, log_data_chunks):
        openai.api_key = OPENAI_API_KEY
        model = OPENAI_API_MODEL
        prompt = "<instruction>Analyze the following log data and identify any unusual or subtle suspicious activity that might not be easily detected by traditional tools or manual inspection. If no such activity is found, reply with 'No suspicious activity detected'.</instruction><code><![CDATA[{'concise': true}]]></code>"
        
        results = []
        futures = {self.executor.submit(self.analyze_single_chunk, model, prompt, chunk): chunk for chunk in log_data_chunks}
        for future in concurrent.futures.as_completed(futures):
            chunk = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                logging.error(f"An exception occurred while analyzing log entries: {exc}")
        
        return results

    def analyze_single_chunk(self, model, prompt, log_data_chunk):
        with self.rate_limiter:
            try:
                if model.startswith("llama"):
                    cmd = ["llama/main", "-p", prompt + str(log_data_chunk)]
                    result = subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
                    return result.stdout.strip()
                elif not model.startswith("gpt-"):
                    response = openai.Completion.create(
                        engine=model,
                        prompt=prompt + str(log_data_chunk),
                        top_p=1,
                        frequency_penalty=0,
                        presence_penalty=0,
                    )
                    return response.choices[0].text.strip()
                else:
                    response = openai.ChatCompletion.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": prompt},
                            {"role": "user", "content": str(log_data_chunk)}
                        ]
                    )
                    return response.choices[0].message.content.strip()
            except openai.errors.RequestError as e:
                logging.error(f"Request error in GPT analysis: {e}")
            except openai.errors.InvalidRequestError as e:
                logging.error(f"Invalid request error in GPT analysis: {e}")
            except openai.errors.AuthenticationError as e:
                logging.error(f"Authentication error in GPT analysis: {e}")
            except openai.errors.RateLimitError as e:
                logging.error(f"Rate limit error in GPT analysis: {e}")
            except Exception as e:
                logging.error(f"Unexpected error in GPT analysis: {e}")
            return None

    def print_to_cli(self, log_entry, result):
        logging.info("-" * 80)
        logging.info("Log Entry:")
        logging.info(log_entry.strip())
        logging.info("\nResults:")
        logging.info(result)
        logging.info("-" * 80 + "\n")

    def flush_buffer(self):
        if self.buffered_entries:
            # Split the buffered entries into chunks for parallel processing
            chunks = self.split_buffer_into_chunks(self.buffered_entries)

            # Process each chunk in parallel using ThreadPoolExecutor
            gpt_results = []
            futures = {self.executor.submit(self.analyze, chunk): chunk for chunk in chunks}
            for future in concurrent.futures.as_completed(futures):
                chunk = futures[future]
                try:
                    gpt_result = future.result()
                    gpt_results.append(gpt_result)
                except Exception as exc:
                    logging.error(f"An exception occurred while analyzing log entries: {exc}")

            # Combine the results from each chunk and print to CLI
            combined_result = "\n".join("\n".join(item) for item in gpt_results)
            self.print_to_cli("GPT Analysis Result:", combined_result)

            # Reset the buffer
            self.buffered_entries = []
            self.token_count = 0

        self.buffer_flush_timer = threading.Timer(BUFFER_FLUSH_INTERVAL, self.flush_buffer)
        self.buffer_flush_timer.start()

    def split_buffer_into_chunks(self, buffered_entries, chunk_size=CHUNK_SIZE):
        return [buffered_entries[i:i + chunk_size] for i in range(0, len(buffered_entries), chunk_size)]

    def send_alert(log_entry, gpt_result, pattern_result):
        # Implement preferred alerting mechanism here
        pass

