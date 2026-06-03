"""
Pydantic Request/Response Models
"""

from typing import List
from pydantic import BaseModel, field_validator

class ScanRequest(BaseModel):
    target: str
    port: int = 443
    mode: str = "full"

    @field_validator("target")
    @classmethod
    def clean_target(cls, v: str) -> str:
        v = v.strip()
        for pfx in ("https://", "http://"):
            if v.startswith(pfx):
                v = v[len(pfx):]
        v = v.split("/")[0]
        if ":" in v and not v.startswith("["):
            host, mp = v.rsplit(":", 1)
            if mp.isdigit():
                v = host
        if not v:
            raise ValueError("Target cannot be empty")
        return v

    @field_validator("port")
    @classmethod
    def valid_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError("Port must be 1–65535")
        return v

class BulkScanRequest(BaseModel):
    targets: List[str]
    port: int = 443
    mode: str = "full"
