from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from enum import Enum

class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class GatewayLogger(ABC):
    """Abstract interface for gateway logging implementations"""
    
    @abstractmethod
    def log_request(self, request_data: Dict[str, Any]) -> None:
        """Log incoming request with full context"""
        pass
    
    @abstractmethod
    def log_response(self, response_data: Dict[str, Any]) -> None:
        """Log outgoing response with timing"""
        pass
    
    @abstractmethod
    def log_auth_event(self, event_data: Dict[str, Any]) -> None:
        """Log authentication/authorization events"""
        pass
    
    @abstractmethod
    def log_validation_error(self, error_data: Dict[str, Any]) -> None:
        """Log validation failures"""
        pass
    
    @abstractmethod
    def log_rate_limit_event(self, limit_data: Dict[str, Any]) -> None:
        """Log rate limiting events"""
        pass
    
    @abstractmethod
    def log_error(self, error_data: Dict[str, Any]) -> None:
        """Log errors and exceptions"""
        pass
    
    @abstractmethod
    def log(self, level: LogLevel, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """General purpose logging with context"""
        pass
