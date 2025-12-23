"""
Data models for Arachne.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator


class SiteStatus(str, Enum):
    """Status of a discovered site."""
    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEAD = "dead"
    HONEYPOT = "honeypot"
    SCAM = "scam"


class SiteCategory(str, Enum):
    """Categories for dark web sites."""
    FORUM = "forum"
    MARKET = "market"
    SERVICE = "service"
    LIBRARY = "library"
    BLOG = "blog"
    MIRROR = "mirror"
    HIDDEN_SERVICE = "hidden_service"
    OTHER = "other"


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Site(BaseModel):
    """Represents a dark web site."""
    id: str = Field(..., description="Unique identifier")
    onion_address: str = Field(..., description="Onion address (56 characters)")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_checked: Optional[datetime] = None
    status: SiteStatus = SiteStatus.DISCOVERED
    category: Optional[SiteCategory] = None
    subcategory: Optional[str] = None
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_level: RiskLevel = RiskLevel.LOW
    language: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    
    @validator('onion_address')
        if not v.endswith('.onion'):
            raise ValueError('Onion address must end with .onion')
        # v3 addresses are 56 characters
        if len(v) != 56 + 6:  # .onion suffix
            raise ValueError('Invalid onion address length')
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class DiscoveryResult(BaseModel):
    """Result of a discovery operation."""
    site: Site
    source_url: Optional[str] = None
    discovery_method: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    raw_content_hash: Optional[str] = None
    processing_time: float = 0.0


class ClassificationResult(BaseModel):
    """Result of classification."""
    site_id: str
    category: SiteCategory
    subcategory: Optional[str]
    confidence: float
    features: Dict[str, Any]
    model_version: str
    processed_at: datetime = Field(default_factory=datetime.utcnow)


class SafetyCheckResult(BaseModel):
    """Result of safety checking."""
    site_id: str
    is_safe: bool
    flagged_categories: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    action_taken: str  # "allow", "block", "review"
    checked_at: datetime = Field(default_factory=datetime.utcnow)


class CrawlJob(BaseModel):
    """Job for crawling a site."""
    id: str
    url: str
    priority: int = 0
    max_depth: int = 1
    created_at: datetime = Field(default_factory=datetime.utcnow)
    scheduled_for: Optional[datetime] = None
    status: str = "pending"
    retry_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SystemMetrics(BaseModel):
    """System performance metrics."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    circuits_active: int
    circuits_total: int
    sites_discovered: int
    sites_classified: int
    requests_per_minute: float
    error_rate: float
    memory_usage_mb: float
    cpu_percent: float        """Validate onion address format."""
    def validate_onion_address(cls, v):
    metadata: Dict[str, Any] = Field(default_factory=dict)
    requires_review: bool = False
    tags: List[str] = Field(default_factory=list)
    is_honeypot: bool = False
