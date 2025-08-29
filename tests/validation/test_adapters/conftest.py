import pytest
import django
from django.conf import settings


def pytest_configure():
    """Configure Django for pytest-django"""
    if not settings.configured:
        settings.configure(
            SECRET_KEY='test-secret-key-for-apigateway-tests',
            DEBUG=True,
            USE_TZ=True,
            DATABASES={
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                }
            },
            INSTALLED_APPS=[
                'django.contrib.contenttypes',
                'django.contrib.auth',
            ],
            ROOT_URLCONF='tests.validation.test_adapters.test_django',
            MIDDLEWARE=[],
        )
        django.setup()
