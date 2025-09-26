import os
from typing import Optional
from .abstract_logger import GatewayLogger, LogLevel
from .json_logger import JsonLogger

# Global logger instance
_global_logger: Optional[GatewayLogger] = None

def configure_logging(
    logger: Optional[GatewayLogger] = None,
    log_level: Optional[LogLevel] = None,
    enable_sampling: bool = False,
    sampling_rate: float = 1.0
) -> GatewayLogger:
    """Configure global logger instance"""
    global _global_logger
    
    if logger is not None:
        _global_logger = logger
    else:
        # Create default JSON logger
        level = log_level or _get_log_level_from_env()
        _global_logger = JsonLogger(
            log_level=level,
            enable_sampling=enable_sampling,
            sampling_rate=sampling_rate
        )
    
    return _global_logger

def get_logger() -> GatewayLogger:
    """Get the global logger instance"""
    global _global_logger
    
    if _global_logger is None:
        # Auto-configure with defaults
        _global_logger = JsonLogger(log_level=_get_log_level_from_env())
    
    return _global_logger

def _get_log_level_from_env() -> LogLevel:
    """Get log level from environment variables"""
    env_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    level_mapping = {
        'DEBUG': LogLevel.DEBUG,
        'INFO': LogLevel.INFO,
        'WARNING': LogLevel.WARNING,
        'ERROR': LogLevel.ERROR,
        'CRITICAL': LogLevel.CRITICAL
    }
    
    return level_mapping.get(env_level, LogLevel.INFO)
