from typing import Dict, Any, List

def default_error_formatter(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert raw validation errors into a consistent list of structured dicts.
    The GatewayValidationError will wrap this into the full error schema.
    """
    formatted = []
    for err in errors:
        field = ".".join(str(loc) for loc in err.get("loc", []))
        message = err.get("msg", "Invalid input")
        error_type = err.get("type", "value_error")
        formatted.append({
            "field": field,
            "message": message,
            "type": error_type,
        })
    return formatted