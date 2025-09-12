# exceptions/RateLimitError.py
from typing import Any, Dict, List, Optional

class RateLimitError(Exception):
    """
    Structured exception for rate limit violations.
    
    Error Envelope (consistent with GatewayValidationError and AuthError):
    {
        "error": str,      # Human-readable message
        "code": str,       # Machine-readable error code  
        "details": dict    # Rate limit details
    }
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        details: Optional[Dict[str, Any]] = None,
        code: str = "rate_limit_exceeded",
    ):
        self.message = message
        self.details = details or []
        self.code = code

        # Consistent payload structure
        payload = {
            "error": self.message,
            "code": self.code,
            "details": self.details,
        }
        super().__init__(payload)

    def __str__(self):
        return f"{self.code.upper()}: {self.message} | Details: {self.details}"

    def __repr__(self):
        return f"RateLimitError(message='{self.message}', code='{self.code}', details={self.details})"


class RateLimitExceeded(RateLimitError):
    """Rate limit exceeded (429)"""
    def __init__(
        self, 
        limit: int, 
        window: int, 
        retry_after: Optional[int] = None,
        current_usage: Optional[int] = None
    ):
        details = {
            "limit": limit,
            "window": window,
            "retry_after": retry_after,
            "current_usage": current_usage
        }
        
        message = f"Rate limit exceeded: {limit} requests per {window} seconds"
        if retry_after:
            message += f". Try again in {retry_after} seconds"
            
        super().__init__(message, details, "rate_limit_exceeded")