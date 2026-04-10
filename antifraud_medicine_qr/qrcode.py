import binascii
from base64 import b64decode
from io import BytesIO

import qrcode
from PIL import Image

from antifraud_medicine_qr.models import EncryptedData, ErrorCorrection


def make(
    encrypted_data: EncryptedData,
    error_correction: ErrorCorrection = ErrorCorrection.Level_M,
    box_size: int = 10,
    border: int = 4,
    logo_content: str | None = None,
) -> BytesIO:
    """Generate a QR code image from encrypted data."""
    data = encrypted_data.model_dump_json()
    qr = qrcode.QRCode(
        version=None,
        error_correction=error_correction.value,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    if hasattr(img, "get_image"):
        img = img.get_image()
    img = img.convert("RGBA")

    if logo_content:
        try:
            logo_bytes = b64decode(logo_content, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("logo_content must be valid base64 image bytes") from exc

        try:
            logo = Image.open(BytesIO(logo_bytes)).convert("RGBA")
        except (OSError, ValueError) as exc:
            raise ValueError("logo_content must decode to a valid image") from exc

        # Remove transparent outer margins so visual logo center aligns with QR center.
        logo_bbox = logo.getbbox()
        if logo_bbox:
            logo = logo.crop(logo_bbox)

        # Keep logo coverage conservative to preserve readability.
        max_logo_size = int(min(img.size) * 0.18)
        logo.thumbnail((max_logo_size, max_logo_size), Image.Resampling.LANCZOS)

        padding = max(2, max_logo_size // 12)
        bg_side = max(logo.width, logo.height) + (2 * padding)
        logo_bg = Image.new("RGBA", (bg_side, bg_side), (255, 255, 255, 255))
        logo_x = (bg_side - logo.width) // 2
        logo_y = (bg_side - logo.height) // 2
        logo_bg.alpha_composite(logo, (logo_x, logo_y))

        x = (img.width - bg_side) // 2
        y = (img.height - bg_side) // 2
        img.alpha_composite(logo_bg, (x, y))

    img = img.convert("RGB")
    img_io = BytesIO()
    img.save(img_io, format="PNG")
    img_io.seek(0)
    return img_io
