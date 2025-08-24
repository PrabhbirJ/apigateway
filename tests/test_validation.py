import pytest
from pydantic import BaseModel
from core.validation import validate_request
from core.enums.validation_modes import ValidationMode

class UserSchema(BaseModel):
    username: str
    age: int

def test_strict_mode_valid_payload():
    @validate_request(UserSchema, ValidationMode.STRICT)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice", "age": 30}
    result = handler(payload)
    assert result.username == "alice"
    assert result.age == 30

def test_strict_mode_extra_field_fails():
    @validate_request(UserSchema, ValidationMode.STRICT)
    def handler(data: UserSchema): 
        return data

    payload = {"username": "alice", "age": 30, "extra": "oops"}
    with pytest.raises(ValueError) as exc:
        handler(payload)
    assert "extra fields not permitted" in str(exc.value)

def test_lax_mode_allows_extra_fields():
    @validate_request(UserSchema, ValidationMode.LAX)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice", "age": 30, "extra": "ok"}
    result = handler(payload)
    assert result.username == "alice"
    assert result.age == 30  # extra is ignored, not stored

def test_missing_required_field():
    @validate_request(UserSchema, ValidationMode.STRICT)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice"}
    with pytest.raises(ValueError) as exc:
        handler(payload)
    assert "field required" in str(exc.value)

def test_custom_error_formatter():
    def fake_formatter(errors):
        return {"custom": errors}

    @validate_request(UserSchema, ValidationMode.STRICT, error_formatter=fake_formatter)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice"}  # missing age
    with pytest.raises(ValueError) as exc:
        handler(payload)
    assert "custom" in str(exc.value)

def test_idempotency_of_payload():
    @validate_request(UserSchema, ValidationMode.STRICT)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice", "age": 30}
    before = payload.copy()
    result = handler(payload)
    assert payload == before  # original dict not mutated
    assert result.dict() == {"username": "alice", "age": 30}