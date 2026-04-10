import hashlib
import json
from datetime import datetime, UTC
from pathlib import Path
from threading import Lock

from antifraud_medicine_qr.models import EncryptedData

_LEDGER_FILE = Path(".ledger") / "chain.json"
_LOCK = Lock()


def _payload_hash(encrypted_data: EncryptedData) -> str:
    payload = json.dumps(encrypted_data.model_dump(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _record_hash(index: int, timestamp: str, payload_hash: str, previous_hash: str) -> str:
    raw = f"{index}:{timestamp}:{payload_hash}:{previous_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _ensure_ledger() -> None:
    if _LEDGER_FILE.exists():
        return

    _LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    genesis_timestamp = datetime.now(UTC).isoformat()
    genesis = {
        "index": 0,
        "timestamp": genesis_timestamp,
        "payload_hash": "GENESIS",
        "previous_hash": "0",
        "hash": _record_hash(0, genesis_timestamp, "GENESIS", "0"),
    }
    _LEDGER_FILE.write_text(json.dumps([genesis], indent=2), encoding="utf-8")


def _load_chain() -> list[dict]:
    _ensure_ledger()
    content = _LEDGER_FILE.read_text(encoding="utf-8")
    return json.loads(content)


def _save_chain(chain: list[dict]) -> None:
    _LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LEDGER_FILE.write_text(json.dumps(chain, indent=2), encoding="utf-8")


def _is_chain_valid(chain: list[dict]) -> bool:
    for i, record in enumerate(chain):
        expected_hash = _record_hash(
            record["index"],
            record["timestamp"],
            record["payload_hash"],
            record["previous_hash"],
        )
        if record["hash"] != expected_hash:
            return False

        if i == 0:
            continue

        if record["previous_hash"] != chain[i - 1]["hash"]:
            return False

    return True


def register_payload(encrypted_data: EncryptedData) -> dict:
    with _LOCK:
        chain = _load_chain()
        if not _is_chain_valid(chain):
            raise ValueError("Ledger integrity check failed")

        payload_hash = _payload_hash(encrypted_data)
        previous = chain[-1]
        index = int(previous["index"]) + 1
        timestamp = datetime.now(UTC).isoformat()
        record_hash = _record_hash(index, timestamp, payload_hash, previous["hash"])
        record = {
            "index": index,
            "timestamp": timestamp,
            "payload_hash": payload_hash,
            "previous_hash": previous["hash"],
            "hash": record_hash,
        }
        chain.append(record)
        _save_chain(chain)
        return record


def verify_payload(record_id: int, encrypted_data: EncryptedData) -> tuple[bool, str]:
    with _LOCK:
        chain = _load_chain()
        if not _is_chain_valid(chain):
            return False, "Ledger integrity check failed"

        if record_id <= 0 or record_id >= len(chain):
            return False, "Record not found"

        payload_hash = _payload_hash(encrypted_data)
        record = chain[record_id]
        if record["payload_hash"] != payload_hash:
            return False, "Payload hash mismatch"

        return True, "Payload verified against local blockchain ledger"
