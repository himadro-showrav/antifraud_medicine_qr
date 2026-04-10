from base64 import b64encode

from antifraud_medicine_qr.models import DecodeRequest, EncodeRequest

LOGO_CONTENT = b64encode(
    bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63f8cfc0f01f00050001ff89993d1d0000000049454e44ae426082"
    )
).decode()


def test_index(client):
    """Test the home page endpoint."""
    response = client.get("/")

    assert response.status_code == 200


def test_encode(client, plaintext, key, company_api_key):
    """Test encoding plaintext to QR code."""
    request = EncodeRequest(plaintext=plaintext, key=key, company_api_key=company_api_key)
    response = client.post("/v1/encode", json=request.model_dump())

    assert response.status_code == 201
    response_data = response.json()
    assert response_data["content"]
    assert response_data["media_type"] == "image/png"
    assert isinstance(response_data["blockchain_record_id"], int)
    assert response_data["blockchain_record_id"] >= 1
    assert response_data["blockchain_hash"]


def test_encode_with_logo(client, plaintext, key, company_api_key):
    """Test encoding plaintext to QR code with logo overlay."""
    request = EncodeRequest(
        plaintext=plaintext,
        key=key,
        company_api_key=company_api_key,
        logo_content=LOGO_CONTENT,
    )
    response = client.post("/v1/encode", json=request.model_dump())

    assert response.status_code == 201
    response_data = response.json()
    assert response_data["content"]
    assert response_data["media_type"] == "image/png"


def test_encode_with_invalid_logo(client, plaintext, key, company_api_key):
    """Test encoding with invalid logo payload returns error."""
    request = EncodeRequest(
        plaintext=plaintext,
        key=key,
        company_api_key=company_api_key,
        logo_content="not-base64",
    )
    response = client.post("/v1/encode", json=request.model_dump())

    assert response.status_code == 400
    response_data = response.json()
    assert response_data["detail"] == "logo_content must be valid base64 image bytes"


def test_decode(client, plaintext, key, sample_encrypted_data):
    """Test decoding QR code to plaintext."""
    request = DecodeRequest(encrypted_data=sample_encrypted_data, key=key)
    response = client.post("/v1/decode", json=request.model_dump())

    assert response.status_code == 201
    response_data = response.json()
    assert response_data["decrypted_data"] == plaintext


def test_decode_error(client, key, sample_encrypted_data):
    """Test decoding with invalid data returns error."""
    encrypted_data = sample_encrypted_data.model_copy(
        update={"associated_data": b64encode(b"invalid-aad").decode()}
    )
    request = DecodeRequest(encrypted_data=encrypted_data, key=key)
    response = client.post("/v1/decode", json=request.model_dump())

    assert response.status_code == 400
    response_data = response.json()
    assert response_data["detail"] == "Signature verification failed"


def test_healthz(client):
    """Test the health check endpoint."""
    response = client.get("/healthz")

    assert response.status_code == 200


def test_verify_blockchain_record(client, sample_encrypted_data):
    """Test successful verification against signed issuance registry."""

    verify_response = client.post(
        "/v1/verify",
        json={
            "encrypted_data": sample_encrypted_data.model_dump(),
        },
    )

    assert verify_response.status_code == 200
    assert verify_response.json()["verified"] is True
    assert verify_response.json()["status"] in {"valid", "suspicious"}


def test_verify_blockchain_payload(client, plaintext, key, company_api_key):
    """Test authenticity verification fails for mismatched payload."""
    encode_request = EncodeRequest(
        plaintext=plaintext,
        key=key,
        company_api_key=company_api_key,
    )
    encode_response = client.post("/v1/encode", json=encode_request.model_dump())
    assert encode_response.status_code == 201

    verify_response = client.post(
        "/v1/verify",
        json={
            "encrypted_data": {
                "salt": "KtiCW1E0VLupOXOtpDIlZQ==",
                "iterations": 1200000,
                "associated_data": "JFPRP6/RMmCIn3DLjA/ceg==",
                "nonce": "LbF9P5FwPYyGCTJM",
                "ciphertext": "/N8WF0+QnqsDhOQ9iWuhWrXgbrZlG4Hqm9cYt/QO9Msu",
            },
        },
    )

    assert verify_response.status_code == 200
    assert verify_response.json()["verified"] is False
    assert verify_response.json()["status"] == "invalid"


def test_encode_requires_company_api_key(client, plaintext, key):
    """Test encode endpoint rejects missing/invalid company key."""
    response = client.post(
        "/v1/encode",
        json={
            "plaintext": plaintext,
            "key": key,
            "company_api_key": "wrong-key",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid company API key"
