from base64 import b64encode

from antifraud_medicine_qr.models import EncryptedData
from antifraud_medicine_qr.qrcode import make

LOGO_CONTENT = b64encode(
    bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63f8cfc0f01f00050001ff89993d1d0000000049454e44ae426082"
    )
).decode()


def test_make():
    """Test QR code generation from encrypted data."""
    encrypted_data = EncryptedData(
        salt="KtiCW1E0VLupOXOtpDIlZQ==",
        iterations=1200000,
        associated_data="JFPRP6/RMmCIn3DLjA/ceg==",
        nonce="LbF9P5FwPYyGCTJM",
        ciphertext="/N8WF0+QnqsDhOQ9iWuhWrXgbrZlG4Hqm9cYt/QO9Msu",
    )

    img_io = make(encrypted_data)
    assert img_io.getbuffer().nbytes > 0


def test_make_with_logo():
    """Test QR code generation with centered logo overlay."""
    encrypted_data = EncryptedData(
        salt="KtiCW1E0VLupOXOtpDIlZQ==",
        iterations=1200000,
        associated_data="JFPRP6/RMmCIn3DLjA/ceg==",
        nonce="LbF9P5FwPYyGCTJM",
        ciphertext="/N8WF0+QnqsDhOQ9iWuhWrXgbrZlG4Hqm9cYt/QO9Msu",
    )

    img_io = make(encrypted_data, logo_content=LOGO_CONTENT)
    assert img_io.getbuffer().nbytes > 0
