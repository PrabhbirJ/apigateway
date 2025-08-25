from functools import wraps #using wraps allows us to ensure that the function where the decorator is used its metadata is copied to the wrapper
from pydantic import BaseModel, ValidationError, ConfigDict
from typing import Callable,Dict,Any,List
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.exceptions.GatewayValidationError import GatewayValidationError




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


def make_schema(base_model: type[BaseModel], allow_extra: bool) -> type[BaseModel]:
    class ConfiguredModel(base_model):
        model_config = ConfigDict(extra="ignore" if allow_extra else "forbid")
    return ConfiguredModel


def validate_request(
    model: type[BaseModel],
    mode: ValidationMode = ValidationMode.STRICT,
    error_formatter: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
):
    allow_extra = (mode == ValidationMode.LAX)
    schema = make_schema(model, allow_extra)

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(request_data, *args, **kwargs):
            try:
                validated = schema.model_validate(
                    request_data,
                    strict=(mode == ValidationMode.STRICT),
                )
                return func(validated, *args, **kwargs)
            except ValidationError as e:
                formatter = error_formatter or default_error_formatter
                details = formatter(e.errors())
                raise GatewayValidationError("Validation Failed", details)
        return wrapper
    return decorator
'''
a simple understanding to what is happening above
say we have a function called create_user where we are using the validate decorator
@validate(MyModel)
def create_user(data:MyModel):
    pass
now what actually happens is
create_user = validate(MyModel)(create_user)
validate(MyModel) returns the decorator to which we pass the function create_user and finally create_user is now the wrapper
wo when we pass the data when we call create_user({name:J,age:22}) this data is passed as the parameter to the wrapper
'''
