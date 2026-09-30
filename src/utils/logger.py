"""Standardized logging utilities for GraphQL Guardian."""

import logging
import sys
from pathlib import Path
from typing import Optional


class ScannerLogger:
    """Standardized logger for scanner modules."""
    
    _loggers = {}  # Cache loggers to avoid duplicates
    
    def __init__(self, name: str, log_file: Optional[str] = None, verbose: bool = False):
        """
        Initialize a logger for a scanner module.
        
        Args:
            name: Logger name (typically module name)
            log_file: Optional log file path
            verbose: If True, show DEBUG messages on console
        """
        # Return cached logger if exists
        if name in ScannerLogger._loggers:
            cached = ScannerLogger._loggers[name]
            self.logger = cached.logger
            return
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        # File handler (if log file specified)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(self._get_formatter())
            self.logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.DEBUG if verbose else logging.INFO)
        ch.setFormatter(self._get_formatter())
        self.logger.addHandler(ch)
        
        # Cache this logger
        ScannerLogger._loggers[name] = self
    
    def _get_formatter(self):
        """Get log formatter."""
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def error(self, msg: str, exc_info: bool = False):
        """Log error message."""
        self.logger.error(msg, exc_info=exc_info)
    
    def warning(self, msg: str):
        """Log warning message."""
        self.logger.warning(msg)
    
    def info(self, msg: str):
        """Log info message."""
        self.logger.info(msg)
    
    def debug(self, msg: str):
        """Log debug message."""
        self.logger.debug(msg)
