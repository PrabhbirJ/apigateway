import uuid
from contextvars import ContextVar
from typing import Optional, Dict, Any

# Context variables for request-scoped data
_correlation_id: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)
_user_id: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
_request_start_time: ContextVar[Optional[float]] = ContextVar('request_start_time', default=None)
_request_path: ContextVar[Optional[str]] = ContextVar('request_path', default=None)
_request_method: ContextVar[Optional[str]] = ContextVar('request_method', default=None)

def set_correlation_id(correlation_id: str) -> None:
    """Set correlation ID for current request context"""
    _correlation_id.set(correlation_id)

def get_correlation_id() -> Optional[str]:
    """Get correlation ID from current request context"""
    return _correlation_id.get()

def set_user_id(user_id: str) -> None:
    """Set user ID for current request context"""
    _user_id.set(user_id)

def get_user_id() -> Optional[str]:
    """Get user ID from current request context"""
    return _user_id.get()

def set_request_start_time(start_time: float) -> None:
    """Set request start time for duration calculation"""
    _request_start_time.set(start_time)

def get_request_start_time() -> Optional[float]:
    """Get request start time"""
    return _request_start_time.get()

def set_request_info(method: str, path: str) -> None:
    """Set request method and path"""
    _request_method.set(method)
    _request_path.set(path)

def get_request_info() -> Dict[str, Optional[str]]:
    """Get request method and path"""
    return {
        'method': _request_method.get(),
        'path': _request_path.get()
    }

def generate_correlation_id() -> str:
    """Generate a new correlation ID"""
    return str(uuid.uuid4())

def get_context_data() -> Dict[str, Any]:
    """Get all current context data for logging"""
    return {
        'correlation_id': get_correlation_id(),
        'user_id': get_user_id(),
        'method': _request_method.get(),
        'path': _request_path.get()
    }

