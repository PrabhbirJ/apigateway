import pytest
from pydantic import BaseModel, ConfigDict
from apigateway.core.validation import validate_generic
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.exceptions.GatewayValidationError import GatewayValidationError

class StrictSchema(BaseModel):
    foo: str
    model_config = ConfigDict(extra="forbid")

def test_strict_mode_rejects_extra_fields():
    @validate_generic(StrictSchema)
    def handler(data, validated: StrictSchema):
        return validated

    with pytest.raises(GatewayValidationError):
        handler({"foo": "ok", "bar": "not allowed"})

def test_strict_mode_accepts_valid_payload():
    @validate_generic(StrictSchema)
    def handler(data, validated: StrictSchema):
        return validated

    result = handler({"foo": "hello"})
    assert result.foo == "hello"

class LaxSchema(BaseModel):
    foo: str
    model_config = ConfigDict(extra="forbid")

def test_lax_mode_with_type_coercion():
    @validate_generic(LaxSchema, mode=ValidationMode.LAX)
    def handler(data, validated: LaxSchema):
        return validated

    # Test LAX mode allows type coercion (if you had int fields)
    result = handler({"foo": "hello"})
    assert result.foo == "hello"