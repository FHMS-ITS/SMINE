import inspect
import timeit
from pathlib import Path

import ujson as json
import os
import logging
from datetime import datetime
from typing import Iterable, Any

from bson.json_util import _json_convert

logger = logging.getLogger(__name__)


class JsonCacheManager:
    def __init__(self, base_path: str):
        self.base_path = base_path
        self.start_time: float | None = None
        os.makedirs(self.base_path, exist_ok=True)

    def start_timer(self) -> None:
        """
        Starts a timer to measure the duration of an operation.
        """
        self.start_time = timeit.default_timer()

    def save(
        self, name: str, result: list | dict, comment: str = "", latex_str: str = ""
    ):
        file_path = os.path.join(self.base_path, f"{name}.json")
        time_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        if hasattr(result, "__iter__") and not isinstance(
            result, (list, dict, str, bytes)
        ):  # for mongodb cursor compatibility
            result = _json_convert(result)

        if self.start_time is None:
            logger.warning("Timer was not started. Duration will be set to null. Call start_timer() before saving.")
            duration_secs = None
        else:
            duration_secs = timeit.default_timer() - self.start_time
            self.start_time = None

        _result = {
            "last_updated": time_now,
            "comment": comment,
            "results": result,
            "latex_str": latex_str,
            "duration_secs": duration_secs,
        }

        try:
            with open(file_path, "w") as file:
                json.dump(_result, file, indent=4)
            logger.info(f"Successfully saved result to file '{name}'")
        except Exception:
            logger.exception(f"An error occurred while saving the file '{name}'")

    def load(self, name: str, all: bool = False) -> Any:
        file_path = os.path.join(self.base_path, f"{name}.json")
        try:
            with open(file_path, "r") as file:
                _result = json.load(file)
            if all:
                return _result
            return _result.get("results")
        except FileNotFoundError:
            logger.error(f"File '{name}' not found")
            return None
        except json.JSONDecodeError as ex:
            logger.error(f"The file contains invalid JSON: {ex!r}.")
            return None
        except Exception:
            logger.exception(f"An error occurred while loading the file '{name}'")
            return None

    def read_json_lines(self, name: str) -> Iterable[dict]:
        file_path = os.path.join(self.base_path, f"{name}.jsonl")
        with open(file_path, "rb") as file:
            yield from (json.loads(line) for line in file)


def get_cache_name(**extra) -> str:
    """
    Generates a cache name based on the caller's file and function name,
    with optional extra parameters.
    """
    current_frame = inspect.currentframe()
    caller_frame = inspect.getouterframes(current_frame, 2)
    caller_file_name = Path(caller_frame[1].filename).stem
    caller_function_name = caller_frame[1].function
    cache_name = f"{caller_file_name}.{caller_function_name}"
    if extra:
        cache_name += "." + ".".join(f"{k}-{v}" for k, v in extra.items())
    return cache_name
