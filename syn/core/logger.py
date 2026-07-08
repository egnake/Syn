"""
SYN - GeliÅŸmiÅŸ Loglama ve Raporlama AltyapÄ±sÄ±
"""

import logging
import os
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler

console = Console()

class UmayLogger:
    def __init__(self, log_level=logging.INFO):
        self.logger = logging.getLogger("syn")
        self.logger.setLevel(log_level)

        if not self.logger.handlers:

            rich_handler = RichHandler(console=console, rich_tracebacks=True, show_time=True, show_path=False)
            rich_handler.setLevel(log_level)
            self.logger.addHandler(rich_handler)

            log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f"umay_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            
            self.logger.addHandler(file_handler)

    def get_logger(self):
        return self.logger

logger = UmayLogger().get_logger()




