# core/logging/decorators.py
import time
import inspect
from functools import wraps
from typing import Callable, Optional, Dict, Any

from .manager import get_logger
from .abstract_logger import GatewayLogger
from .context import (
    set_correlation_id, generate_correlation_id, set_user_id, 
    set_request_start_time, set_request_info, get_correlation_id,
    get_request_start_time
)

from ..adapters.base_adapter import FrameworkAdapter
from ..adapters.flask import FlaskAdapter
from ..adapters.django import DjangoAdapter
from ..adapters.fastapi import FastAPIAdapter
from ..adapters.generic import GenericAdapter

def log_request(
    adapter: Optional[FrameworkAdapter] = None,
    logger: Optional[GatewayLogger] = None,
    correlation_header: str = "X-Correlation-ID"
):
    """
    Framework-agnostic request logging decorator.
    Should be the OUTERMOST decorator in the stack.
    
    Args:
        adapter: Framework adapter (if None, uses GenericAdapter)
        logger: Logger instance (if None, uses global logger)
        correlation_header: Header name for correlation ID
    
    Order in decorator stack (outermost to innermost):
        @log_request_flask()          # <- OUTERMOST (sees everything)
        @rate_limit_flask(...)
        @authorize_flask([...])  
        @validate_flask(...)
        def endpoint():              # <- INNERMOST
            pass
    """
    
    if adapter is None:
        adapter = GenericAdapter()
    
    if logger is None:
        logger = get_logger()
    
    def decorator(func: Callable):
        is_async = inspect.iscoroutinefunction(func)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Start timing
            start_time = time.time()
            set_request_start_time(start_time)
            
            # Extract request info
            request_info = adapter.extract_request_logging_info(*args, **kwargs)
            
            # Set up context
            correlation_id = (
                request_info.get('headers', {}).get(correlation_header.lower()) or 
                generate_correlation_id()
            )
            set_correlation_id(correlation_id)
            set_request_info(request_info.get('method', 'UNKNOWN'), request_info.get('path', '/'))
            
            # Log request start
            logger.log_request({
                'method': request_info.get('method'),
                'path': request_info.get('path'),
                'headers': request_info.get('headers', {}),
                'query_params': request_info.get('query_params', {}),
                'client_ip': request_info.get('client_ip'),
                'user_agent': request_info.get('user_agent'),
                'content_type': request_info.get('content_type'),
                'content_length': request_info.get('content_length')
            })
            
            try:
                # Call the decorated function
                result = await func(*args, **kwargs)
                
                # Calculate duration
                duration = time.time() - start_time
                
                # Extract response info
                response_info = adapter.extract_response_logging_info(result)
                
                # Set user context if available (from auth decorators)
                user_context = kwargs.get('user')
                if user_context:
                    set_user_id(str(user_context.get('user_id', user_context.get('sub'))))
                
                # Log successful response
                logger.log_response({
                    'status': response_info.get('status', 200),
                    'duration_ms': round(duration * 1000, 2),
                    'response_size': response_info.get('size'),
                    'cache_status': response_info.get('cache_status')
                })
                
                return result
                
            except Exception as e:
                # Calculate duration for error case
                duration = time.time() - start_time
                
                # Log error
                logger.log_error({
                    'component': 'gateway',
                    'message': f'Request failed: {str(e)}',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e),
                    'duration_ms': round(duration * 1000, 2),
                    'status': getattr(e, 'status_code', 500)
                })
                
                # Re-raise the exception
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Same logic for sync functions
            start_time = time.time()
            set_request_start_time(start_time)
            
            request_info = adapter.extract_request_logging_info(*args, **kwargs)
            
            correlation_id = (
                request_info.get('headers', {}).get(correlation_header.lower()) or 
                generate_correlation_id()
            )
            set_correlation_id(correlation_id)
            set_request_info(request_info.get('method', 'UNKNOWN'), request_info.get('path', '/'))
            
            logger.log_request({
                'method': request_info.get('method'),
                'path': request_info.get('path'),
                'headers': request_info.get('headers', {}),
                'query_params': request_info.get('query_params', {}),
                'client_ip': request_info.get('client_ip'),
                'user_agent': request_info.get('user_agent'),
                'content_type': request_info.get('content_type'),
                'content_length': request_info.get('content_length')
            })
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                response_info = adapter.extract_response_logging_info(result)
                
                user_context = kwargs.get('user')
                if user_context:
                    set_user_id(str(user_context.get('user_id', user_context.get('sub'))))
                
                logger.log_response({
                    'status': response_info.get('status', 200),
                    'duration_ms': round(duration * 1000, 2),
                    'response_size': response_info.get('size'),
                    'cache_status': response_info.get('cache_status')
                })
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                logger.log_error({
                    'component': 'gateway',
                    'message': f'Request failed: {str(e)}',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e),
                    'duration_ms': round(duration * 1000, 2),
                    'status': getattr(e, 'status_code', 500)
                })
                
                raise
        
        return async_wrapper if is_async else sync_wrapper
    return decorator


# Framework-specific convenience functions
def log_request_flask(
    logger: Optional[GatewayLogger] = None,
    correlation_header: str = "X-Correlation-ID"
):
    """Convenience function for Flask request logging"""
    return log_request(
        adapter=FlaskAdapter(),
        logger=logger,
        correlation_header=correlation_header
    )

def log_request_django(
    logger: Optional[GatewayLogger] = None,
    correlation_header: str = "X-Correlation-ID"
):
    """Convenience function for Django request logging"""
    return log_request(
        adapter=DjangoAdapter(),
        logger=logger,
        correlation_header=correlation_header
    )

def log_request_fastapi(
    logger: Optional[GatewayLogger] = None,
    correlation_header: str = "X-Correlation-ID"
):
    """Convenience function for FastAPI request logging"""
    return log_request(
        adapter=FastAPIAdapter(),
        logger=logger,
        correlation_header=correlation_header
    )

def log_request_generic(
    logger: Optional[GatewayLogger] = None,
    correlation_header: str = "X-Correlation-ID"
):
    """Convenience function for generic framework request logging"""
    return log_request(
        adapter=GenericAdapter(),
        logger=logger,
        correlation_header=correlation_header
    )


# Extended base adapter interface for logging
# This needs to be added to your existing base_adapter.py

def extract_request_logging_info_mixin(self, *args, **kwargs) -> Dict[str, Any]:
    """
    Extract comprehensive request information for logging.
    This should be implemented in each framework adapter.
    
    Returns:
        Dict containing:
        - method: HTTP method
        - path: Request path
        - headers: Request headers (dict, lowercased keys)
        - query_params: Query parameters
        - client_ip: Client IP address
        - user_agent: User agent string
        - content_type: Content-Type header
        - content_length: Content length
    """
    # Default implementation - should be overridden
    return {
        'method': 'UNKNOWN',
        'path': '/',
        'headers': {},
        'query_params': {},
        'client_ip': 'unknown',
        'user_agent': 'unknown',
        'content_type': None,
        'content_length': None
    }

def extract_response_logging_info_mixin(self, response) -> Dict[str, Any]:
    """
    Extract response information for logging.
    
    Args:
        response: Framework-specific response object
        
    Returns:
        Dict containing:
        - status: HTTP status code
        - size: Response size in bytes
        - cache_status: Cache status (hit/miss/etc)
    """
    # Default implementation
    return {
        'status': 200,
        'size': None,
        'cache_status': None
    }


# Usage examples and integration notes:
"""
# Example 1: Flask with full logging stack
from gateway.core.logging.decorators import log_request_flask
from gateway.core.auth import authorize_flask
from gateway.core.validation import validate_flask
from gateway.core.rate_limiting import rate_limit_flask

@log_request_flask()                    # OUTERMOST - sees everything
@rate_limit_flask(10, 60)              # Rate limiting
@authorize_flask(['user'])             # Authentication  
@validate_flask(UserSchema)           # Validation
def create_user(validated: UserSchema, user: dict):  # INNERMOST
    return {"success": True, "user": validated.username}

# Example 2: Custom logger
from gateway.core.logging import configure_logging, JsonLogger, LogLevel

# Configure custom logger
custom_logger = JsonLogger(
    log_level=LogLevel.DEBUG,
    enable_sampling=True,
    sampling_rate=0.1  # Log 10% of requests in high-traffic scenarios
)
configure_logging(custom_logger)

@log_request_flask(logger=custom_logger)
def high_traffic_endpoint():
    return {"data": "lots of traffic"}

# Example 3: Custom correlation header
@log_request_flask(correlation_header="X-Request-ID")  # Use different header
def api_endpoint():
    return {"api": "response"}

# Example 4: Access logger in endpoint
from gateway.core.logging import get_logger

@log_request_flask()
@authorize_flask(['admin'])
def admin_action(user: dict):
    logger = get_logger()
    logger.log(LogLevel.INFO, "Admin performed sensitive action", {
        'action': 'user_deletion',
        'target_user': 'user123'
    })
    return {"action": "completed"}

# Example 5: Multiple endpoints with consistent logging
class APIEndpoints:
    @log_request_flask()
    @rate_limit_flask(100, 60)
    def public_endpoint(self):
        return {"public": True}
    
    @log_request_flask()
    @authorize_flask(['user'])
    @rate_limit_flask(50, 60)
    def protected_endpoint(self, user: dict):
        return {"protected": True, "user": user['username']}

# Log output examples:
# Request start:
{
    "timestamp": "2025-01-20T15:30:45.123Z",
    "level": "info", 
    "component": "gateway",
    "message": "Request received",
    "correlation_id": "abc-123-def",
    "method": "POST",
    "path": "/api/users",
    "event_type": "request_start",
    "request": {
        "method": "POST",
        "path": "/api/users", 
        "headers": {"content-type": "application/json", "authorization": "***MASKED***"},
        "client_ip": "192.168.1.100",
        "user_agent": "curl/7.68.0"
    }
}

# Request complete:
{
    "timestamp": "2025-01-20T15:30:45.456Z",
    "level": "info",
    "component": "gateway", 
    "message": "Response sent",
    "correlation_id": "abc-123-def",
    "user_id": "user123",
    "method": "POST",
    "path": "/api/users",
    "event_type": "request_complete",
    "response": {
        "status": 201,
        "duration_ms": 333.45,
        "response_size": 156
    }
}
"""