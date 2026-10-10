"""File logging configuration with setting-controlled level and retention."""

import logging
import threading
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

_LOCK = threading.RLock()
_LOGGER_NAME = "privsentinel"
_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def configure_logging(
    logs_directory: str | Path,
    log_level: str,
    retention_days: int,
    file_logging_enabled: bool = True,
) -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if not isinstance(log_level, str):
        raise TypeError("Log level must be a string.")
    level = _LOG_LEVELS.get(log_level)
    if level is None:
        raise ValueError(f"Unsupported log level: {log_level!r}.")
    if type(retention_days) is not int:
        raise TypeError("Log retention must be an integer.")
    if not 1 <= retention_days <= 3650:
        raise ValueError("Log retention must be between 1 and 3650 days.")
    with _LOCK:
        logger.setLevel(level)
        logger.propagate = False
        for handler in tuple(logger.handlers):
            if getattr(handler, "_privsentinel_managed", False):
                logger.removeHandler(handler)
                handler.close()
        if file_logging_enabled:
            directory = Path(logs_directory)
            directory.mkdir(parents=True, exist_ok=True)
            handler = TimedRotatingFileHandler(
                directory / "privsentinel.log",
                when="midnight",
                interval=1,
                backupCount=retention_days,
                encoding="utf-8",
                delay=True,
            )
            handler._privsentinel_managed = True
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s %(name)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            logger.addHandler(handler)
    return logger