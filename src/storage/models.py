"""
Document models for certificate and scan result data.
"""
from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum

class CertificateDocument(BaseModel):
    """Model for certificate documents stored in OpenSearch."""
    serial_number: str
    version: str
    signature_algorithm: Dict[str, Any]
    issuer: Dict[str, str]
    subject: Dict[str, str]
    subject_alternative_names: List[str] = Field(default_factory=list)
    validity: Dict[str, Any] = Field(
        ...,
        description="Certificate validity period with 'not_before', 'not_after', and 'is_valid' fields"
    )
    public_key: Dict[str, Any]
    key_usage: List[str] = Field(default_factory=list)
    extended_key_usage: List[str] = Field(default_factory=list)
    basic_constraints: Dict[str, Any] = Field(default_factory=dict)
    is_self_signed: bool = False
    ct_log_entries: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str
    
    class Config:
        schema_extra = {
            "example": {
                "serial_number": "1234567890abcdef",
                "version": "v3",
                "signature_algorithm": {
                    "name": "sha256WithRSAEncryption",
                    "is_quantum_vulnerable": True
                },
                "issuer": {
                    "commonName": "Example CA",
                    "organizationName": "Example Org",
                    "countryName": "US"
                },
                "subject": {
                    "commonName": "example.com",
                    "organizationName": "Example Inc.",
                    "countryName": "US"
                },
                "subject_alternative_names": ["example.com", "www.example.com"],
                "validity": {
                    "not_before": "2023-01-01T00:00:00Z",
                    "not_after": "2024-01-01T23:59:59Z",
                    "is_valid": True
                },
                "public_key": {
                    "type": "RSA",
                    "key_size": 2048
                },
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "extended_key_usage": ["serverAuth", "clientAuth"],
                "basic_constraints": {
                    "is_ca": False,
                    "path_length": None
                },
                "is_self_signed": False,
                "ct_log_entries": [
                    {
                        "log_id": "example-log-id",
                        "timestamp": "2023-01-01T12:00:00Z",
                        "entry_type": "precert"
                    }
                ],
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            }
        }

class ScanResultDocument(BaseModel):
    """Model for TLS scan result documents stored in OpenSearch."""
    domain: str
    timestamp: str
    ports: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    created_at: str
    
    @validator('timestamp', 'created_at')
    def validate_iso_format(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError("Timestamp must be in ISO 8601 format")
    
    class Config:
        schema_extra = {
            "example": {
                "domain": "example.com",
                "timestamp": "2023-01-01T12:00:00Z",
                "ports": {
                    "443": {
                        "port": 443,
                        "supported_ciphersuites": [
                            {
                                "name": "TLS_AES_128_GCM_SHA256",
                                "tls_version": "TLSv1.3",
                                "security": "secure",
                                "is_quantum_safe": False
                            }
                        ],
                        "tls_versions": {
                            "TLSv1.2": True,
                            "TLSv1.3": True
                        }
                    }
                },
                "created_at": "2023-01-01T12:00:00Z"
            }
        }

class ScanStatus(str, Enum):
    """Status of a domain scan."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanRequest(BaseModel):
    """Model for requesting a new scan."""
    domain: str
    ports: List[int] = [443, 8443]
    force_rescan: bool = False
    
    class Config:
        schema_extra = {
            "example": {
                "domain": "example.com",
                "ports": [443, 8443],
                "force_rescan": False
            }
        }

class CertificateSearchParams(BaseModel):
    """Model for certificate search parameters."""
    query: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    is_quantum_vulnerable: Optional[bool] = None
    expires_before: Optional[str] = None
    expires_after: Optional[str] = None
    limit: int = 100
    offset: int = 0
    
    @validator('expires_before', 'expires_after')
    def validate_date_format(cls, v):
        if v is None:
            return v
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError("Date must be in ISO 8601 format")
    
    class Config:
        schema_extra = {
            "example": {
                "query": "example.com",
                "is_quantum_vulnerable": True,
                "limit": 50,
                "offset": 0
            }
        }
