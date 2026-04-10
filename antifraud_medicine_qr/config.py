from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    model_config = SettingsConfigDict(env_prefix="antifraud_medicine_qr_")
    pbkdf2_iterations: int = Field(description="PBKDF2 iterations", default=1_500_000)
    company_api_key: str = Field(
        description="API key required for company-only QR encoding",
        default="company-encode-key",
    )
    signing_key: str = Field(
        description="Secret key used to sign issued QR payload metadata",
        default="local-signing-key-change-in-production",
    )


settings = Settings()
