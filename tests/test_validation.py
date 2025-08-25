import pytest
from pydantic import BaseModel, ConfigDict
from apigateway.core.validation import validate_request
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.exceptions.GatewayValidationError import GatewayValidationError


class UserSchema(BaseModel):
    username: str
    age: int

    model_config = ConfigDict(extra="forbid")


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
    with pytest.raises(GatewayValidationError) as exc:
        handler(payload)

    err = exc.value.args[0]  # dict passed into GatewayValidationError
    assert err["error"] == "Validation Failed"
    assert err["details"][0]["field"] == "extra"
    assert err["details"][0]["message"] == "Extra inputs are not permitted"


def test_lax_mode_allows_extra_fields():
    @validate_request(UserSchema, ValidationMode.LAX)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice", "age": 30, "extra": "ok"}
    result = handler(payload)
    assert result.username == "alice"
    assert result.age == 30  # extra ignored


def test_missing_required_field():
    @validate_request(UserSchema, ValidationMode.STRICT)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice"}  # missing age
    with pytest.raises(GatewayValidationError) as exc:
        handler(payload)

    err = exc.value.args[0]
    assert err["error"] == "Validation Failed"
    assert any("Field required" in d["message"] for d in err["details"])


def test_custom_error_formatter():
    def fake_formatter(errors):
        return {"custom": errors}

    @validate_request(UserSchema, ValidationMode.STRICT, error_formatter=fake_formatter)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice"}  # missing age
    with pytest.raises(GatewayValidationError) as exc:
        handler(payload)

    err = exc.value.args[0]
    assert "custom" in err["details"]


def test_idempotency_of_payload():
    @validate_request(UserSchema, ValidationMode.STRICT)
    def handler(data: UserSchema):
        return data

    payload = {"username": "alice", "age": 30}
    before = payload.copy()
    result = handler(payload)
    assert payload == before  # original dict untouched
    assert result.model_dump() == {"username": "alice", "age": 30}


if __name__ == "__main__":
    exit_code = pytest.main(["-v", "-s", __file__])
    if exit_code == 0:
        print("All tests passed ✅")
    else:
        print(f"Some tests failed ❌ (exit code {exit_code})")