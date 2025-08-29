import pytest
import json
from django.http import JsonResponse
from django.urls import path
from pydantic import BaseModel, ConfigDict
from apigateway.core.validation import validate_django
from apigateway.core.enums.validation_modes import ValidationMode


# --- Schemas ---
class UserSchema(BaseModel):
    username: str
    age: int
    model_config = ConfigDict(extra="ignore")


class ContactSchema(BaseModel):
    name: str
    email: str
    model_config = ConfigDict(extra="ignore")


class SearchSchema(BaseModel):
    query: str
    limit: int = 10
    model_config = ConfigDict(extra="ignore")


# --- Views ---
@validate_django(UserSchema,mode=ValidationMode.PERMISSIVE)
def create_user_json(request, validated: UserSchema):
    return JsonResponse({
        "message": "User created",
        "username": validated.username,
        "age": validated.age
    })


@validate_django(ContactSchema,mode=ValidationMode.PERMISSIVE)
def submit_contact_form(request, validated: ContactSchema):
    return JsonResponse({
        "name": validated.name,
        "email": validated.email
    })


@validate_django(SearchSchema, mode=ValidationMode.PERMISSIVE)
def search_view(request, validated: SearchSchema):
    return JsonResponse({
        "query": validated.query,
        "limit": validated.limit
    })


@validate_django(UserSchema,mode=ValidationMode.PERMISSIVE)
def create_user_mixed(request, validated: UserSchema):
    return JsonResponse({"success": True, "data": validated.model_dump()})


# --- URL patterns for Django routing ---
urlpatterns = [
    path('users/json/', create_user_json, name='create_user_json'),
    path('contact/', submit_contact_form, name='submit_contact_form'),
    path('search/', search_view, name='search'),
    path('users/mixed/', create_user_mixed, name='create_user_mixed'),
]


# --- Tests ---

@pytest.mark.django_db
def test_django_json_validation(client):
    response = client.post(
        '/users/json/',
        data=json.dumps({"username": "alice", "age": 25}),
        content_type='application/json'
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "alice"
    assert data["age"] == 25
    assert data["message"] == "User created"


@pytest.mark.django_db
def test_django_form_data_validation(client):
    response = client.post('/contact/', {
        'name': 'Bob',
        'email': 'bob@test.com'
    })
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Bob"
    assert data["email"] == "bob@test.com"


@pytest.mark.django_db
def test_django_query_params_validation(client):
    response = client.get('/search/?query=python&limit=5')
    assert response.status_code == 200
    data = response.json()
    assert data["query"] == "python"
    assert data["limit"] == 5


@pytest.mark.django_db
def test_django_validation_errors(client):
    response = client.post(
        '/users/json/',
        data=json.dumps({"username": "alice"}),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert "error" in response.json()

    response = client.post(
        '/users/json/',
        data=json.dumps({"username": "alice", "age": 25, "extra_field": "not_allowed"}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post('/users/json/', data=json.dumps({}), content_type='application/json')
    assert response.status_code == 400


@pytest.mark.django_db
def test_django_malformed_json(client):
    response = client.post(
        '/users/json/',
        data='{"username": "alice", "age":}',  # invalid JSON
        content_type='application/json'
    )
    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert "Invalid JSON" in data["error"]


@pytest.mark.django_db
def test_django_mixed_data_sources(client):
    response = client.post(
        '/users/mixed/?extra_param=test',
        data=json.dumps({"username": "test", "age": 30}),
        content_type='application/json'
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["username"] == "test"
    assert data["data"]["age"] == 30
