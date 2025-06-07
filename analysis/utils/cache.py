import inspect
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
        os.makedirs(self.base_path, exist_ok=True)

    def save(
        self, name: str, result: list | dict, comment: str = "", latex_str: str = ""
    ):
        file_path = os.path.join(self.base_path, f"{name}.json")
        time_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        if hasattr(result, "__iter__") and not isinstance(
            result, (list, dict, str, bytes)
        ):  # for mongodb cursor compatibility
            result = _json_convert(result)

        _result = {
            "last_updated": time_now,
            "comment": comment,
            "results": result,
            "latex_str": latex_str,
        }

        try:
            with open(file_path, "w") as file:
                json.dump(_result, file, indent=4)
            logger.info(f"Successfully saved result to file '{name}'")
        except Exception:
            logger.exception(f"An error occurred while saving the file '{name}'")

    def save_json_lines(self, name: str, result: Iterable[Any]):
        file_path = os.path.join(self.base_path, f"{name}.jsonl")

        result = _json_convert(result)

        try:
            with open(file_path, "w") as file:
                for line in result:
                    json_line = json.dumps(line)
                    file.write(json_line + "\n")  # JSONL = one JSON object per line
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


if __name__ == "__main__":
    jc = JsonCacheManager("test")

    test_result = [{"r1": "1"}, {"r2": "2"}]

    jc.save_json_lines("temp.json", test_result)
