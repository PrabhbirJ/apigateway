import pytest
from pydantic import BaseModel, ConfigDict
from apigateway.core.validation import validate_generic
from apigateway.exceptions.GatewayValidationError import GatewayValidationError

def test_default_error_handling_gives_details():
    class FooSchema(BaseModel):
        foo: int
        model_config = ConfigDict(extra="forbid")

    @validate_generic(FooSchema)
    def handler(validated: FooSchema):
        return validated

    with pytest.raises(GatewayValidationError) as exc:
        handler({"foo": "not-an-int"})

    assert "foo" in str(exc.value)

def test_custom_error_formatter_applied():
    def silly_formatter(errors):
        return [{"oops": "yeah"}]

    class FooSchema(BaseModel):
        foo: int
        model_config = ConfigDict(extra="forbid")

    @validate_generic(FooSchema, error_formatter=silly_formatter)
    def handler(validated: FooSchema):
        return validated

    with pytest.raises(GatewayValidationError) as exc:
        handler({"foo": "bad"})
    assert exc.value.details == [{"oops": "yeah"}]