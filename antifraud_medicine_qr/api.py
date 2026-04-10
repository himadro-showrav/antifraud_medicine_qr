from base64 import b64encode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from antifraud_medicine_qr.blockchain import register_payload
from antifraud_medicine_qr.config import settings
from antifraud_medicine_qr.crypto import decrypt, encrypt
from antifraud_medicine_qr.exceptions import DecryptError
from antifraud_medicine_qr.issuance import check_payload, issue_payload
from antifraud_medicine_qr.models import (
    DecodeRequest,
    DecodeResponse,
    DecryptErrorResponse,
    EncodeRequest,
    EncodeResponse,
    HealthResponse,
    PublicMedicineInfo,
    VerifyRequest,
    VerifyResponse,
)
from antifraud_medicine_qr.qrcode import make

app = FastAPI(
    title="Antifraud Medicine QR",
    description="Detect and prevent counterfeit medicines using encrypted QR codes with blockchain verification",
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.globals["url_for"] = app.url_path_for


@app.exception_handler(DecryptError)
def decrypt_error_exception_handler(request: Request, exc: DecryptError):
    """Handle DecryptError exceptions by returning a JSON error response."""
    return JSONResponse(
        status_code=400,
        content={"message": "Incorrect decryption, please check your data"},
    )


@app.get("/", response_class=HTMLResponse, tags=["home"])
def index(request: Request):
    """Render the home page template."""
    return templates.TemplateResponse(request, "index.html")


@app.post("/v1/encode", status_code=201, tags=["api"])
def encode(request: EncodeRequest) -> EncodeResponse:
    """Encrypt plaintext data and generate a QR code image."""
    if request.company_api_key != settings.company_api_key:
        raise HTTPException(status_code=401, detail="Invalid company API key")

    encrypted_data = encrypt(request.plaintext, request.key)
    public_metadata = None
    if all(
        [
            request.manufacturer_name,
            request.manufacture_date,
            request.medicine_name,
            request.serial_number,
        ]
    ):
        public_metadata = PublicMedicineInfo(
            manufacturer_name=request.manufacturer_name,
            manufacture_date=request.manufacture_date,
            expiry_date=request.expiry_date,
            medicine_name=request.medicine_name,
            serial_number=request.serial_number,
        )

    encrypted_data = issue_payload(encrypted_data, public_metadata=public_metadata)
    try:
        block = register_payload(encrypted_data)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        img_io = make(
            encrypted_data,
            error_correction=request.error_correction,
            box_size=request.box_size,
            border=request.border,
            logo_content=request.logo_content,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return EncodeResponse(
        content=b64encode(img_io.getvalue()).decode(),
        media_type="image/png",
        blockchain_record_id=block["index"],
        blockchain_hash=block["hash"],
    )


@app.post(
    "/v1/decode",
    status_code=201,
    responses={400: {"model": DecryptErrorResponse, "description": "Incorrect decryption"}},
    tags=["api"],
)
def decode(request: DecodeRequest) -> DecodeResponse:
    """Decrypt encrypted data from a QR code."""
    verify_result = check_payload(request.encrypted_data, increment_scan=False)
    if not verify_result["verified"]:
        raise HTTPException(status_code=400, detail=verify_result["message"])

    decrypted_data = decrypt(request.encrypted_data, request.key)
    return DecodeResponse(decrypted_data=decrypted_data)


@app.post("/v1/verify", status_code=200, tags=["api"])
def verify(request: VerifyRequest) -> VerifyResponse:
    """Verify encrypted payload against local blockchain-like issuance registry."""
    result = check_payload(request.encrypted_data)
    legacy_warning = None
    if request.encrypted_data.public_metadata is not None:
        legacy_warning = (
            "Legacy QR detected: this code contains embedded public metadata that may be readable "
            "by generic QR scanners. Re-issue with the latest format to keep details server-side only."
        )

    # Keep legacy local chain endpoint behavior available when old record_id flow is used.
    if request.encrypted_data.record_id is None:
        return VerifyResponse(
            verified=False,
            status="invalid",
            message="Missing record id in QR payload",
            warning=legacy_warning,
            record_id=None,
            scan_count=0,
            public_metadata=None,
        )

    return VerifyResponse(
        verified=result["verified"],
        status=result["status"],
        message=result["message"],
        warning=legacy_warning,
        record_id=result.get("record_id"),
        scan_count=result.get("scan_count", 0),
        public_metadata=result.get("public_metadata"),
    )


@app.get("/healthz", tags=["healthcheck"])
def healthz() -> HealthResponse:
    """Health check endpoint to verify service availability."""
    return HealthResponse(success=True)
