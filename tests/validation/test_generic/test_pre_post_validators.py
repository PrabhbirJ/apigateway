import pytest
from pydantic import BaseModel, ConfigDict
from apigateway.core.validation import validate_generic, PreValidators
from apigateway.exceptions.GatewayValidationError import GatewayValidationError

def test_pre_validator_normalizes_email():
    class EmailSchema(BaseModel):
        email: str
        model_config = ConfigDict(extra="forbid")

    @validate_generic(EmailSchema, pre_validators=[PreValidators.normalize_email])
    def handler(data, validated: EmailSchema):  
        return validated

    result = handler({"email": "  USER@Example.COM "})
    assert result.email == "user@example.com"

def test_post_validator_enforces_business_rule():
    class SalarySchema(BaseModel):
        role: str
        salary: int
        model_config = ConfigDict(extra="forbid")

    def enforce_min_salary(model: SalarySchema) -> SalarySchema:
        if model.role == "admin" and model.salary < 100000:
            raise ValueError("Admin too cheap!")
        return model

    @validate_generic(SalarySchema, post_validators=[enforce_min_salary])
    def handler(data, validated: SalarySchema):
        return validated

    # ok case
    result = handler({"role": "admin", "salary": 120000})
    assert result.salary == 120000

    # failing case
    with pytest.raises(GatewayValidationError):
        handler({"role": "admin", "salary": 50000})