"""
SYN - Logging and Console Infrastructure
"""

import logging
import os
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from syn.core.config import get_logs_dir

console = Console()


class UmayLogger:
    """Manages Rich console logging and lazy file logging."""

    def __init__(self, console_level: int = logging.INFO):
        self.logger = logging.getLogger("syn")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self._file_handler_added = False

        if not self.logger.handlers:
            rich_handler = RichHandler(
                console=console,
                rich_tracebacks=True,
                show_time=True,
                show_path=False,
                markup=False,
            )
            rich_handler.setLevel(console_level)
            self.logger.addHandler(rich_handler)

    def enable_file_logging(self, log_dir: Optional[str] = None) -> Optional[str]:
        """Lazily attach a file handler so importing the package creates no files."""
        if self._file_handler_added:
            return None

        target_dir = log_dir or get_logs_dir()
        try:
            os.makedirs(target_dir, exist_ok=True)
            log_file = os.path.join(
                target_dir,
                f"syn_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            )
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            self._file_handler_added = True
            return log_file
        except OSError as exc:
            self.logger.warning(f"[SYSTEM] Could not initialize log file in '{target_dir}': {exc}")
            return None

    def get_logger(self) -> logging.Logger:
        return self.logger


_logger_manager = UmayLogger()
logger = _logger_manager.get_logger()


def enable_file_logging(log_dir: Optional[str] = None) -> Optional[str]:
    """Enable file logging for CLI execution sessions."""
    return _logger_manager.enable_file_logging(log_dir=log_dir)
