import os
from dotenv import load_dotenv

load_dotenv()
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# Default model is gpt-3.5-turbo
OPENAI_API_MODEL = os.getenv("OPENAI_API_MODEL", "gpt-3.5-turbo")
# Default flush interval is 60 seconds
BUFFER_FLUSH_INTERVAL = int(os.getenv("BUFFER_FLUSH_INTERVAL", 60))  
# Default buffer size limit is 1000 entries
BUFFER_SIZE_LIMIT = int(os.getenv("BUFFER_SIZE_LIMIT", 1000))  
# Hugging face API
HUGGING_FACE_API_KEY = os.getenv("HUGGING_FACE_API_KEY", "none")
HUGGING_FACE_MODEL = os.getenv("HUGGING_FACE_MODEL")

# Determines the number of worker threads used for parallel processing. Adjust based on the available CPU resources and the desired level of concurrency
MAX_WORKERS = 4
# Adjust chunk_size based on desired granularity
CHUNK_SIZE = 500