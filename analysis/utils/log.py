import logging
import os
from datetime import datetime


def set_up_logging(
    log_level=logging.DEBUG,
    write_file: bool = False,
    log_dir_base: str = "logs",
    log_dir_sub: str = "",
    log_name: str = datetime.now().strftime("%Y%m%d_%H%M%S"),
):
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(module)s - %(message)s"
    )

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if write_file:
        log_dir_path = os.path.join(log_dir_base, log_dir_sub)
        if not os.path.isdir(log_dir_path):
            os.makedirs(log_dir_path)
        log_file_path = os.path.join(log_dir_path, log_name)
        handlers.append(logging.FileHandler(filename=log_file_path, mode="w"))

    logger = logging.getLogger()
    logger.setLevel(log_level)
    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
