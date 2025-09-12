# exceptions/AuthError.py
from typing import Any, Dict, List, Optional

class AuthError(Exception):
    """
    Structured exception for API Gateway authentication/authorization errors.
    
    Error Envelope (consistent with GatewayValidationError):
    {
        "error": str,      # Human-readable message
        "code": str,       # Machine-readable error code
        "details": Any     # Additional context (customizable)
    }
    """

    def __init__(
        self,
        message: str = "Authorization Failed",
        details: Optional[List[Dict[str, Any]]] = None,
        code: str = "authorization_error",
    ):
        self.message = message
        self.details = details or []
        self.code = code

        # Consistent payload structure with GatewayValidationError
        payload = {
            "error": self.message,
            "code": self.code,
            "details": self.details,
        }
        super().__init__(payload)

    def __str__(self):
        return f"{self.code.upper()}: {self.message} | Details: {self.details}"

    def __repr__(self):
        return f"AuthError(message='{self.message}', code='{self.code}', details={self.details})"


# Specific auth error types for better error handling
class AuthenticationError(AuthError):
    """User authentication failed (401)"""
    def __init__(self, message: str = "Authentication required", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, details, "authentication_required")


class AuthorizationError(AuthError):
    """User authorization failed (403)"""
    def __init__(self, message: str = "Access denied", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, details, "access_denied")


class TokenError(AuthError):
    """Token-related errors"""
    def __init__(self, message: str = "Invalid token", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message, details, "token_error")