import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, Set, List
from .abstract_logger import GatewayLogger, LogLevel
from .context import get_context_data

class JsonLogger(GatewayLogger):
    """Default JSON logger implementation using Python's logging module"""
    
    def __init__(
        self, 
        logger_name: str = "gateway",
        log_level: LogLevel = LogLevel.INFO,
        masked_fields: Optional[Set[str]] = None,
        enable_sampling: bool = False,
        sampling_rate: float = 1.0
    ):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(getattr(logging, log_level.value.upper()))
        
        # Set up JSON formatter if no handlers exist
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(JsonFormatter())
            self.logger.addHandler(handler)
        
        # Default masked fields
        self.masked_fields = masked_fields or {
            'authorization', 'password', 'cookie', 'x-api-key', 
            'token', 'secret', 'auth', 'credentials'
        }
        
        self.enable_sampling = enable_sampling
        self.sampling_rate = sampling_rate
        self._sample_counter = 0
    
    def _should_log(self) -> bool:
        """Determine if this log entry should be recorded (for sampling)"""
        if not self.enable_sampling:
            return True
        
        self._sample_counter += 1
        return (self._sample_counter % int(1 / self.sampling_rate)) == 0
    
    def _mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively mask sensitive fields in data"""
        if not isinstance(data, dict):
            return data
        
        masked = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(masked_field in key_lower for masked_field in self.masked_fields):
                masked[key] = "***MASKED***"
            elif isinstance(value, dict):
                masked[key] = self._mask_sensitive_data(value)
            elif isinstance(value, list):
                masked[key] = [
                    self._mask_sensitive_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                masked[key] = value
        
        return masked
    
    def _create_log_entry(
        self, 
        level: LogLevel, 
        component: str, 
        message: str, 
        extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create standardized log entry with context"""
        entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': level.value,
            'component': component,
            'message': message,
            **get_context_data()  # Add correlation_id, user_id, method, path
        }
        
        if extra:
            # Mask sensitive data in extra fields
            masked_extra = self._mask_sensitive_data(extra)
            entry.update(masked_extra)
        
        # Remove None values
        return {k: v for k, v in entry.items() if v is not None}
    
    def log_request(self, request_data: Dict[str, Any]) -> None:
        """Log incoming request"""
        if not self._should_log():
            return
        
        entry = self._create_log_entry(
            LogLevel.INFO,
            "gateway",
            "Request received",
            {
                'request': self._mask_sensitive_data(request_data),
                'event_type': 'request_start'
            }
        )
        self.logger.info(json.dumps(entry))
    
    def log_response(self, response_data: Dict[str, Any]) -> None:
        """Log outgoing response"""
        if not self._should_log():
            return
        
        entry = self._create_log_entry(
            LogLevel.INFO,
            "gateway", 
            "Response sent",
            {
                'response': response_data,
                'event_type': 'request_complete'
            }
        )
        self.logger.info(json.dumps(entry))
    
    def log_auth_event(self, event_data: Dict[str, Any]) -> None:
        """Log authentication/authorization events"""
        level = LogLevel.ERROR if event_data.get('success') is False else LogLevel.INFO
        
        entry = self._create_log_entry(
            level,
            "auth",
            event_data.get('message', 'Authentication event'),
            {
                **self._mask_sensitive_data(event_data),
                'event_type': 'auth_event'
            }
        )
        
        if level == LogLevel.ERROR:
            self.logger.error(json.dumps(entry))
        else:
            self.logger.info(json.dumps(entry))
    
    def log_validation_error(self, error_data: Dict[str, Any]) -> None:
        """Log validation failures"""
        entry = self._create_log_entry(
            LogLevel.WARNING,
            "validation",
            error_data.get('message', 'Validation failed'),
            {
                **error_data,
                'event_type': 'validation_error'
            }
        )
        self.logger.warning(json.dumps(entry))
    
    def log_rate_limit_event(self, limit_data: Dict[str, Any]) -> None:
        """Log rate limiting events"""
        entry = self._create_log_entry(
            LogLevel.WARNING,
            "rate_limit",
            limit_data.get('message', 'Rate limit triggered'),
            {
                **limit_data,
                'event_type': 'rate_limit'
            }
        )
        self.logger.warning(json.dumps(entry))
    
    def log_error(self, error_data: Dict[str, Any]) -> None:
        """Log errors and exceptions"""
        entry = self._create_log_entry(
            LogLevel.ERROR,
            error_data.get('component', 'gateway'),
            error_data.get('message', 'Error occurred'),
            {
                **error_data,
                'event_type': 'error'
            }
        )
        self.logger.error(json.dumps(entry))
    
    def log(self, level: LogLevel, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """General purpose logging"""
        if not self._should_log():
            return
        
        entry = self._create_log_entry(level, "gateway", message, extra)
        
        log_method = getattr(self.logger, level.value)
        log_method(json.dumps(entry))


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        # If the message is already JSON, return as-is
        try:
            json.loads(record.getMessage())
            return record.getMessage()
        except (json.JSONDecodeError, ValueError):
            # Not JSON, wrap in standard structure
            log_entry = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'level': record.levelname.lower(),
                'component': 'gateway',
                'message': record.getMessage(),
                'logger': record.name
            }
            
            # Add exception info if present
            if record.exc_info:
                log_entry['exception'] = self.formatException(record.exc_info)
            
            return json.dumps(log_entry)
