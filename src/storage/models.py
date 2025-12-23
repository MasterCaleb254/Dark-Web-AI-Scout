"""
SQLAlchemy models for Arachne database.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, 
    DateTime, JSON, Text, ForeignKey, Enum, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import JSONB
import uuid

Base = declarative_base()


class Site(Base):
    """Dark web site entity."""
    __tablename__ = 'sites'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    onion_address = Column(String(56), unique=True, nullable=False, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_checked = Column(DateTime)
    last_changed = Column(DateTime)
    
    # Status
    status = Column(
        Enum('discovered', 'active', 'inactive', 'dead', 'honeypot', 'scam', name='site_status'),
        default='discovered',
        nullable=False
    )
    
    # Classification
    category = Column(
        Enum('forum', 'market', 'service', 'library', 'blog', 'mirror', 'hidden_service', 'other', name='site_category')
    )
    subcategory = Column(String(100))
    risk_score = Column(Float, default=0.0)
    risk_level = Column(Enum('low', 'medium', 'high', 'critical', name='risk_level'), default='low')
    
    # Content info
    language = Column(String(10))
    title = Column(Text)
    title_hash = Column(String(64))  # SHA256 of title for deduplication
    description = Column(Text)
    
    # Safety flags
    is_honeypot = Column(Boolean, default=False)
    requires_review = Column(Boolean, default=False)
    is_illegal = Column(Boolean, default=False)
    
    # Metadata
    tags = Column(ARRAY(String))
    metadata = Column(JSONB)
    
    # Relationships
    discovery_results = relationship("DiscoveryResult", back_populates="site", cascade="all, delete-orphan")
    classifications = relationship("Classification", back_populates="site", cascade="all, delete-orphan")
    safety_checks = relationship("SafetyCheck", back_populates="site", cascade="all, delete-orphan")
    crawl_jobs = relationship("CrawlJob", back_populates="site", cascade="all, delete-orphan")
    
    __table_args__ = (
        UniqueConstraint('title_hash', 'language', name='uq_title_language'),
        {'postgresql_partition_by': 'HASH(onion_address)'}
    )
    
    def __repr__(self):
        return f"<Site(onion_address={self.onion_address}, status={self.status})>"


class DiscoveryResult(Base):
    """Result of discovering a site."""
    __tablename__ = 'discovery_results'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id = Column(UUID(as_uuid=True), ForeignKey('sites.id'), nullable=False, index=True)
    
    # Discovery info
    source_url = Column(Text)
    discovery_method = Column(
        Enum('seed', 'crawl', 'directory', 'social', 'api', name='discovery_method'),
        nullable=False
    )
    
    # Metrics
    confidence = Column(Float, default=0.0)
    raw_content_hash = Column(String(64))  # SHA256 of raw content
    processing_time = Column(Float)
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    site = relationship("Site", back_populates="discovery_results")


class Classification(Base):
    """Classification result for a site."""
    __tablename__ = 'classifications'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id = Column(UUID(as_uuid=True), ForeignKey('sites.id'), nullable=False, index=True)
    
    # Classification
    category = Column(
        Enum('forum', 'market', 'service', 'library', 'blog', 'mirror', 'hidden_service', 'other', name='site_category'),
        nullable=False
    )
    subcategory = Column(String(100))
    confidence = Column(Float, nullable=False)
    
    # Model info
    model_version = Column(String(50), nullable=False)
    model_type = Column(
        Enum('rule_based', 'ml_supervised', 'ml_unsupervised', 'hybrid', name='model_type'),
        nullable=False
    )
    
    # Features
    features = Column(JSONB)
    
    # Timestamps
    classified_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    site = relationship("Site", back_populates="classifications")


class SafetyCheck(Base):
    """Safety check result for a site."""
    __tablename__ = 'safety_checks'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id = Column(UUID(as_uuid=True), ForeignKey('sites.id'), nullable=False, index=True)
    
    # Result
    is_safe = Column(Boolean, nullable=False)
    action_taken = Column(
        Enum('allow', 'block', 'review', 'quarantine', name='safety_action'),
        nullable=False
    )
    
    # Flags
    flagged_categories = Column(ARRAY(String))
    risk_factors = Column(ARRAY(String))
    
    # Metadata
    filter_version = Column(String(50))
    checked_content_hash = Column(String(64))
    
    # Timestamps
    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    site = relationship("Site", back_populates="safety_checks")


class CrawlJob(Base):
    """Job for crawling a site."""
    __tablename__ = 'crawl_jobs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id = Column(UUID(as_uuid=True), ForeignKey('sites.id'), nullable=False, index=True)
    
    # Job info
    url = Column(Text, nullable=False)
    priority = Column(Integer, default=0)
    max_depth = Column(Integer, default=1)
    
    # Status
    status = Column(
        Enum('pending', 'running', 'completed', 'failed', 'retry', name='job_status'),
        default='pending',
        nullable=False
    )
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Results
    error_message = Column(Text)
    discovered_links = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    scheduled_for = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Metadata
    metadata = Column(JSONB)
    
    # Relationship
    site = relationship("Site", back_populates="crawl_jobs")


class ContentHash(Base):
    """Hashes of content for deduplication and safety checking."""
    __tablename__ = 'content_hashes'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_id = Column(UUID(as_uuid=True), ForeignKey('sites.id'), nullable=False, index=True)
    
    # Hash info
    hash_type = Column(
        Enum('title', 'image_phash', 'text_simhash', 'document', name='hash_type'),
        nullable=False
    )
    hash_value = Column(String(128), nullable=False, index=True)
    algorithm = Column(String(50), nullable=False)
    
    # Content info
    content_size = Column(Integer)
    mime_type = Column(String(100))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        UniqueConstraint('site_id', 'hash_type', name='uq_site_hash_type'),
    )


class SystemMetrics(Base):
    """System performance metrics."""
    __tablename__ = 'system_metrics'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Metrics
    circuits_active = Column(Integer)
    circuits_total = Column(Integer)
    sites_discovered = Column(Integer)
    sites_classified = Column(Integer)
    safety_checks_performed = Column(Integer)
    
    # Performance
    requests_per_minute = Column(Float)
    error_rate = Column(Float)
    avg_response_time = Column(Float)
    
    # Resources
    memory_usage_mb = Column(Float)
    cpu_percent = Column(Float)
    disk_usage_mb = Column(Float)
    
    # Tor stats
    tor_traffic_read = Column(Integer)  # bytes
    tor_traffic_written = Column(Integer)  # bytes
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class AuditLog(Base):
    """Audit log for all system actions."""
    __tablename__ = 'audit_logs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Action info
    component = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    status = Column(
        Enum('success', 'failure', 'warning', name='audit_status'),
        nullable=False
    )
    
    # User/Agent
    researcher_id = Column(UUID(as_uuid=True), nullable=True)
    user_agent = Column(String(500))
    ip_address = Column(String(45))  # IPv6 compatible
    
    # Details
    details = Column(JSONB)
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    __table_args__ = (
        Index('idx_audit_component_action', 'component', 'action'),
        Index('idx_audit_timestamp_status', 'timestamp', 'status'),
    )
