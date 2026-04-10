from enum import IntEnum

from pydantic import BaseModel, Field


class PublicMedicineInfo(BaseModel):
    """Public medicine information visible to verifiers without decryption key."""

    manufacturer_name: str = Field(min_length=1, max_length=120)
    manufacture_date: str = Field(min_length=1, max_length=40)
    expiry_date: str | None = Field(default=None, max_length=40)
    medicine_name: str = Field(min_length=1, max_length=120)
    serial_number: str = Field(min_length=1, max_length=80)


class EncryptedData(BaseModel):
    """Model representing encrypted data with all necessary components."""

    salt: str
    iterations: int
    associated_data: str
    nonce: str
    ciphertext: str
    record_id: str | None = None
    issued_at: str | None = None
    signature: str | None = None
    public_metadata: PublicMedicineInfo | None = None


class ErrorCorrection(IntEnum):
    """Enumeration for QR code error correction levels."""

    Level_L = 1
    Level_M = 0
    Level_Q = 3
    Level_H = 2


class EncodeRequest(BaseModel):
    """Request model for encoding plaintext to QR code."""

    plaintext: str = Field(min_length=1, max_length=2048, description="Text to be encrypted")
    key: str = Field(min_length=1, max_length=32, description="Key used to encrypt the data")
    company_api_key: str = Field(
        min_length=1,
        description="Company API key. Required for encode operation.",
    )
    error_correction: ErrorCorrection = Field(
        default=ErrorCorrection.Level_M,
        description="Error correction level, possible values: 1 (About 7% or less errors can be corrected), 0 (About 15% or less errors can be corrected), 3 (About 25% or less errors can be corrected), 2 (About 30% or less errors can be corrected)",
    )
    box_size: int = Field(default=10, description="How many pixels each 'box' of the QR code is")
    border: int = Field(default=4, description="How many boxes thick the border should be")
    logo_content: str | None = Field(
        default=None,
        description="Optional base64-encoded logo image (PNG/JPEG/WebP). If provided, it is centered in the QR code.",
    )
    manufacturer_name: str | None = Field(default=None, max_length=120)
    manufacture_date: str | None = Field(default=None, max_length=40)
    expiry_date: str | None = Field(default=None, max_length=40)
    medicine_name: str | None = Field(default=None, max_length=120)
    serial_number: str | None = Field(default=None, max_length=80)


class EncodeResponse(BaseModel):
    """Response model for encode operation containing QR code image data."""

    content: str = Field(description="Image content encoded in base64")
    media_type: str = Field(description="The media type of the image")
    blockchain_record_id: int | None = Field(
        default=None,
        description="Local blockchain-like ledger record id for this encrypted payload",
    )
    blockchain_hash: str | None = Field(
        default=None,
        description="Hash for the corresponding ledger block",
    )


class DecodeRequest(BaseModel):
    """Request model for decoding QR code to plaintext."""

    encrypted_data: EncryptedData = Field(description="The encrypted data read from the image")
    key: str = Field(min_length=1, max_length=32, description="Key used to encrypt the data")


class DecodeResponse(BaseModel):
    """Response model for decode operation containing decrypted plaintext."""

    decrypted_data: str = Field(description="The result decrypted data")


class VerifyRequest(BaseModel):
    """Request model for public QR authenticity verification."""

    encrypted_data: EncryptedData = Field(description="The encrypted data read from QR code")


class VerifyResponse(BaseModel):
    """Response model for authenticity verification and duplicate scan detection."""

    verified: bool = Field(description="Whether payload matches the blockchain record")
    status: str = Field(description="Verification status: valid, suspicious, or invalid")
    message: str = Field(description="Verification detail message")
    warning: str | None = Field(
        default=None,
        description="Optional warning message, e.g. for legacy QR formats.",
    )
    record_id: str | None = Field(default=None, description="Issued record identifier from QR metadata")
    scan_count: int = Field(description="How many times this QR has been scanned via verify")
    public_metadata: PublicMedicineInfo | None = Field(
        default=None,
        description="Public medicine metadata for user-facing verification",
    )


class DecryptErrorResponse(BaseModel):
    """Response model for decryption error."""

    message: str


class HealthResponse(BaseModel):
    """Response model for health check endpoint."""

    success: bool
