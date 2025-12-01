"""
IOC Data Models
All IOC data structures defined here
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
import uuid


# =====================================================
# ENUMS - Fixed list of options
# =====================================================

class IOCType(str, Enum):
    """What TYPE is the IOC?"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    FILE_HASH_MD5 = "hash_md5"
    FILE_HASH_SHA1 = "hash_sha1"
    FILE_HASH_SHA256 = "hash_sha256"
    CVE = "cve"
    ASN = "asn"


class IOCRole(str, Enum):
    """What kind of threat is this IOC?"""
    MALWARE = "malware"
    BOTNET = "botnet"
    COMMAND_AND_CONTROL = "c2"
    PHISHING = "phishing"
    SPAM = "spam"
    DDoS = "ddos"
    EXPLOIT = "exploit"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class TLPLevel(str, Enum):
    """Traffic Light Protocol - data sharing level"""
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


# =====================================================
# BASE IOC MODEL - Core fields
# =====================================================

class IOC(BaseModel):
    """
    Base IOC (Indicator of Compromise) data model.
    This is the main object we store in MongoDB.
    """

    # ===== IDENTIFICATION =====
    ioc_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this IOC"
    )

    # ===== THE ACTUAL IOC VALUE =====
    indicator: str = Field(
        ...,
        description="The actual IOC value (IP, domain, hash, etc.)",
        example="8.8.8.8"
    )

    ioc_type: IOCType = Field(
        ...,
        description="Type of indicator",
        example=IOCType.IPV4
    )

    # ===== THREAT CLASSIFICATION =====
    role: IOCRole = Field(
        default=IOCRole.UNKNOWN,
        description="What kind of threat is this?"
    )

    # ===== CONFIDENCE: How sure are we? =====
    confidence: int = Field(
        ge=0,
        le=100,
        default=50,
        description="Confidence score 0-100"
    )

    reputation_score: int = Field(
        ge=-100,
        le=100,
        default=0,
        description="Reputation score -100 (bad) to 100 (good)"
    )

    # ===== SOURCE: Where did we get this? =====
    source: str = Field(
        ...,
        description="Source of this IOC",
        example="OTX"
    )

    source_feed_name: Optional[str] = Field(
        default=None,
        description="Specific feed within source",
        example="Malware Analysis Pulse"
    )

    source_reference_url: Optional[str] = Field(
        default=None,
        description="URL to original report/source"
    )

    # ===== TIMESTAMPS: When did we see this? =====
    first_seen: Optional[datetime] = Field(
        default_factory=datetime.utcnow,
        description="When was this IOC first observed?"
    )

    last_seen: Optional[datetime] = Field(
        default_factory=datetime.utcnow,
        description="When was this IOC last observed?"
    )

    last_updated: Optional[datetime] = Field(
        default_factory=datetime.utcnow,
        description="When was the record last updated?"
    )

    # ===== SHARING & STATUS =====
    tlp: TLPLevel = Field(
        default=TLPLevel.WHITE,
        description="Traffic Light Protocol level"
    )

    is_active: bool = Field(
        default=True,
        description="Is this IOC still active/relevant?"
    )

    # ===== DESCRIPTION & TAGS =====
    title: Optional[str] = Field(
        default=None,
        description="Human-readable title"
    )

    description: Optional[str] = Field(
        default=None,
        description="Detailed description"
    )

    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
        example=["malware", "emotet"]
    )

    # ===== THREAT CONTEXT =====
    malware_families: List[str] = Field(
        default_factory=list,
        description="Associated malware families"
    )

    threat_actors: List[str] = Field(
        default_factory=list,
        description="Associated threat actors/APT groups"
    )

    campaigns: List[str] = Field(
        default_factory=list,
        description="Associated campaigns"
    )

    # ===== FLEXIBLE METADATA =====
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Any extra data"
    )

    class Config:
        use_enum_values = False
        json_schema_extra = {
            "example": {
                "indicator": "8.8.8.8",
                "ioc_type": "ipv4",
                "role": "command_and_control",
                "confidence": 95,
                "source": "OTX",
                "description": "C&C Server"
            }
        }


# =====================================================
# TYPE-SPECIFIC IOC MODELS (Extended)
# =====================================================

class GeoLocation(BaseModel):
    """Geographic information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    is_vpn: Optional[bool] = None
    is_datacenter: Optional[bool] = None


class IPAddressIOC(IOC):
    """IOC for IP addresses with extra IP-specific fields"""

    geo_location: Optional[GeoLocation] = None
    reverse_dns: Optional[str] = None
    whois_owner: Optional[str] = None
    is_scanning: bool = Field(default=False, description="Known for scanning?")
    is_botnet: bool = Field(default=False, description="Part of botnet?")
    is_c2_server: bool = Field(default=False, description="C&C server?")


class DomainIOC(IOC):
    """IOC for domains with extra domain-specific fields"""

    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    is_newly_registered: bool = Field(default=False)
    resolved_ips: List[str] = Field(default_factory=list, description="IPs this domain resolves to")
    is_phishing: bool = Field(default=False)
    is_parking: bool = Field(default=False, description="Domain parking/sinkhole?")


class FileHashIOC(IOC):
    """IOC for file hashes with extra file-specific fields"""

    md5_hash: Optional[str] = None
    sha1_hash: Optional[str] = None
    sha256_hash: Optional[str] = None

    filename: Optional[str] = None
    file_size: Optional[int] = None

    av_detection_count: int = Field(default=0, description="How many AV engines detected?")
    av_detection_ratio: str = Field(default="0/0", description="detected/total format")
