from functools import wraps #using wraps allows us to ensure that the function where the decorator is used its metadata is copied to the wrapper
from pydantic import BaseModel, ValidationError
from typing import Callable,Dict,Any,List
from core.enums.validation_modes import ValidationMode


def default_error_formatter(errors: List[Dict[str,Any]]) -> Dict[str,Any]:
    formatted = []
    for err in errors:
        field = ".".join(str(loc) for loc in err.get("loc", []))
        message = err.get("msg", "Invalid input")
        error_type = err.get("type", "value_error")
        formatted.append({"field": field, "message": message, "type": error_type})
    return {"error": "Validation Failed", "details": formatted}


#decorator factory
def validate_request(
    model: type[BaseModel],
    mode: ValidationMode = ValidationMode.STRICT,
    error_formatter: Callable[[List[Dict[str, Any]]], Dict[str, Any]] | None = None
):
    """
    Decorator to validate incoming request data against a specified Pydantic model.

    Example:
        @validate(MyModel)
        def create_user(data: MyModel):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(request_data, *args,**kwargs):
            try:
                if mode == ValidationMode.STRICT:
                    validated = model.model_validate(request_data)
                    return func(validated,*args,**kwargs)
                else:
                    validated = model.model_validate(request_data,strict=False)
                    return func(validated,*args,**kwargs)
            except ValidationError as e:
                formatter = error_formatter or default_error_formatter
                return formatter(e.errors())
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
