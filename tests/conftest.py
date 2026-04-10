import pytest
from fastapi.testclient import TestClient

from antifraud_medicine_qr.api import app
from antifraud_medicine_qr.config import settings
from antifraud_medicine_qr.crypto import encrypt
from antifraud_medicine_qr.issuance import issue_payload


@pytest.fixture
def key():
    """Fixture providing a test encryption key."""
    return "my super secret key"


@pytest.fixture
def plaintext():
    """Fixture providing test plaintext data."""
    return "super secret text"


@pytest.fixture
def company_api_key():
    """Fixture providing company-only encode API key."""
    return settings.company_api_key


@pytest.fixture
def sample_encrypted_data(plaintext, key):
    """Issued encrypted payload for testing decode and verify operations."""
    encrypted_data = encrypt(plaintext, key)
    return issue_payload(encrypted_data)


@pytest.fixture
def client():
    """Fixture providing a FastAPI test client."""
    return TestClient(app)
