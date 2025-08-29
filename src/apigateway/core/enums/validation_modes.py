from enum import Enum
class ValidationMode(str, Enum):
    '''
    STRICT = forbid extras, strict validation
    LAX = forbid extras, loose coercion
    PERMISSVE = forbid or ignore extras, loose coercion
    '''
    STRICT = "strict"
    LAX = "lax"
    PERMISSIVE = "permissive"