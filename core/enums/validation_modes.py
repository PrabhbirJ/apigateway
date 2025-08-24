from enum import Enum
class ValidationMode(str, Enum):
    STRICT = "strict"
    LAX = "lax"