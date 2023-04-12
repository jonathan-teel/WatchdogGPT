#!/usr/bin/env python3
import os
import re
import time
import logging
import threading
import openai
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

load_dotenv()
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LOG_FORMAT = os.getenv("LOG_FILE_FORMAT")
OPENAI_API_MODEL = os.getenv("OPENAI_API_MODEL", "gpt-3.5-turbo")

class WatchdogGPT(FileSystemEventHandler):

    def __init__(self):
        self.buffered_entries = []
        self.MAX_TOKENS = 2048  # Tokens sent + tokens returned limit
        self.token_count = 0
        self.print_to_cli("Info:", "Starting WatchdogGPT")

    def on_modified(self, event):
        if not event.is_directory and event.src_path == LOG_FILE_PATH:
            self.process_log_update()

    def process_log_update(self):
        new_entries = self.read_buffered_log_entries()

       # self.print_to_cli("Current Buffer Size:", str(self.token_count))

        for entry in new_entries:
            preprocessed_entry = self.preprocess_log_entry(entry, format=LOG_FORMAT)

            if preprocessed_entry:
                entry_tokens = len(entry.split())

                if self.token_count + entry_tokens > self.MAX_TOKENS:
                    entries_to_process = self.buffered_entries
                    self.buffered_entries = []
                    self.token_count = 0
                    gpt_result = self.analyze(entries_to_process)
                    self.print_to_cli("GPT Analysis Result:", gpt_result)
                else:
                    self.buffered_entries.append(preprocessed_entry)
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

    def preprocess_log_entry(self, entry, format='CLF'):
        if format == 'CLF':
            pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)'
        elif format == 'ELFF':
            pattern = r'(\S+) (\S+) (\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)'

        match = re.match(pattern, entry)

        if match:
            return match.groups()

        return None

    def analyze(self, log_data):
        openai.api_key = OPENAI_API_KEY
        model = OPENAI_API_MODEL
        prompt = "Analyze the following log data and report any suspicious activity or hacking attempts. If none, simply reply 'No suspicious activity'."
        try:
            if model.startswith("llama"):
                cmd = ["llama/main", "-p", prompt + str(log_data)]
                result = subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
                return result.stdout.strip()
            elif not model.startswith("gpt-"):
                response = openai.Completion.create(
                    engine=model,
                    prompt=prompt + str(log_data),
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
                        {"role": "user", "content": str(log_data)}
                    ]
                )
                return result = response.choices[0].message.content.strip()
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

    def send_alert(log_entry, gpt_result, pattern_result):
        # Implement preferred alerting mechanism here
        pass


def main():
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'watchdoggpt_analysis.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file_path)
        ]
    )
    wdgpt = WatchdogGPT()
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

if __name__ == '__main__':
    main()
