# exceptions/gateway_error.py
from typing import Any

class GatewayValidationError(Exception):
    """
    Structured exception for API Gateway validation errors.

    Error Envelope (always returned):
    {
        "error": str,      # Human-readable
        "code": str,       # Machine-readable code
        "details": Any     # Schema-specific details (customizable shape)
    }

    - `error` and `code` are fixed across the system.
    - `details` can be customized via `error_formatter`.
    """

    def __init__(
        self,
        message: str = "Validation Failed",
        details: list[dict[str, Any]] | None = None,
        code: str = "validation_error",
    ):
        self.message = message
        self.details = details or []
        self.code = code

        payload = {
            "error": self.message,
            "code": self.code,
            "details": self.details,
        }
        super().__init__(payload)

    def __str__(self):
        return f"{self.code.upper()}: {self.message} | Details: {self.details}"