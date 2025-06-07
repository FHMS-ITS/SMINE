import logging
import os

LOG_DIR = "smime_chain_verifier/logs"

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")


# Filter to allow only INFO level
class OnlyInfoFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO


# Filter to allow only DEBUG and INFO levels
class OnlyDebugAndInfoFilter(logging.Filter):
    def filter(self, record):
        return record.levelno in (logging.DEBUG, logging.INFO)


# info.log: Only INFO messages, overwrite file on each run
info_handler = logging.FileHandler(f"{LOG_DIR}/init_cache.log", mode="w")
info_handler.setLevel(logging.INFO)
info_handler.addFilter(OnlyInfoFilter())
info_handler.setFormatter(formatter)
logger.addHandler(info_handler)

# debug.log: DEBUG and INFO messages, overwrite file on each run
debug_handler = logging.FileHandler(f"{LOG_DIR}/init_cache.debug.log", mode="w")
debug_handler.setLevel(logging.DEBUG)
debug_handler.addFilter(OnlyDebugAndInfoFilter())
debug_handler.setFormatter(formatter)
logger.addHandler(debug_handler)

# error.log: ERROR and above messages, overwrite file on each run
error_handler = logging.FileHandler(f"{LOG_DIR}/init_cache.error.log", mode="w")
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(formatter)
logger.addHandler(error_handler)
