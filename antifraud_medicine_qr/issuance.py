import hashlib
import hmac
import json
from datetime import datetime, UTC
from pathlib import Path
from threading import Lock
from uuid import uuid4

from antifraud_medicine_qr.config import settings
from antifraud_medicine_qr.models import EncryptedData, PublicMedicineInfo

_REGISTRY_FILE = Path(".ledger") / "issued.json"
_LOCK = Lock()


def _ensure_registry() -> None:
    if _REGISTRY_FILE.exists():
        return

    _REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _REGISTRY_FILE.write_text(json.dumps({"records": {}}, indent=2), encoding="utf-8")


def _load_registry() -> dict:
    _ensure_registry()
    content = _REGISTRY_FILE.read_text(encoding="utf-8")
    return json.loads(content)


def _save_registry(registry: dict) -> None:
    _REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _REGISTRY_FILE.write_text(json.dumps(registry, indent=2), encoding="utf-8")


def _payload_hash(encrypted_data: EncryptedData) -> str:
    payload = {
        "salt": encrypted_data.salt,
        "iterations": encrypted_data.iterations,
        "associated_data": encrypted_data.associated_data,
        "nonce": encrypted_data.nonce,
        "ciphertext": encrypted_data.ciphertext,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _sign(record_id: str, issued_at: str, payload_hash: str) -> str:
    message = f"{record_id}:{issued_at}:{payload_hash}".encode()
    return hmac.new(settings.signing_key.encode(), message, hashlib.sha256).hexdigest()


def issue_payload(
    encrypted_data: EncryptedData,
    *,
    public_metadata: PublicMedicineInfo | None = None,
) -> EncryptedData:
    with _LOCK:
        registry = _load_registry()
        record_id = str(uuid4())
        issued_at = datetime.now(UTC).isoformat()
        payload_hash = _payload_hash(encrypted_data)
        signature = _sign(record_id, issued_at, payload_hash)

        registry["records"][record_id] = {
            "record_id": record_id,
            "issued_at": issued_at,
            "payload_hash": payload_hash,
            "signature": signature,
            "public_metadata": public_metadata.model_dump() if public_metadata else None,
            "scan_count": 0,
            "last_scan_at": None,
        }
        _save_registry(registry)

    return encrypted_data.model_copy(
        update={
            "record_id": record_id,
            "issued_at": issued_at,
            "signature": signature,
        }
    )


def check_payload(encrypted_data: EncryptedData, *, increment_scan: bool = True) -> dict:
    with _LOCK:
        record_id = encrypted_data.record_id
        issued_at = encrypted_data.issued_at
        signature = encrypted_data.signature

        if not record_id or not issued_at or not signature:
            return {
                "verified": False,
                "status": "invalid",
                "message": "Missing authenticity metadata",
                "record_id": record_id,
                "scan_count": 0,
                "public_metadata": None,
            }

        registry = _load_registry()
        record = registry.get("records", {}).get(record_id)
        if not record:
            return {
                "verified": False,
                "status": "invalid",
                "message": "Record not issued by this company",
                "record_id": record_id,
                "scan_count": 0,
                "public_metadata": None,
            }

        payload_hash = _payload_hash(encrypted_data)
        expected_signature = _sign(record_id, issued_at, payload_hash)
        if not hmac.compare_digest(expected_signature, signature):
            return {
                "verified": False,
                "status": "invalid",
                "message": "Signature verification failed",
                "record_id": record_id,
                "scan_count": int(record.get("scan_count", 0)),
                "public_metadata": record.get("public_metadata"),
            }

        if payload_hash != record.get("payload_hash"):
            return {
                "verified": False,
                "status": "invalid",
                "message": "Payload mismatch with issued record",
                "record_id": record_id,
                "scan_count": int(record.get("scan_count", 0)),
                "public_metadata": record.get("public_metadata"),
            }

        if increment_scan:
            record["scan_count"] = int(record.get("scan_count", 0)) + 1
            record["last_scan_at"] = datetime.now(UTC).isoformat()
            _save_registry(registry)

        current_scan_count = int(record.get("scan_count", 0))

        if not increment_scan:
            return {
                "verified": True,
                "status": "valid",
                "message": "Valid company-issued QR code",
                "record_id": record_id,
                "scan_count": current_scan_count,
                "public_metadata": record.get("public_metadata"),
            }

        if current_scan_count == 1:
            return {
                "verified": True,
                "status": "valid",
                "message": "Valid company-issued QR code",
                "record_id": record_id,
                "scan_count": current_scan_count,
                "public_metadata": record.get("public_metadata"),
            }

        return {
            "verified": True,
            "status": "suspicious",
            "message": "Duplicate scan detected for this QR code",
            "record_id": record_id,
            "scan_count": current_scan_count,
            "public_metadata": record.get("public_metadata"),
        }
