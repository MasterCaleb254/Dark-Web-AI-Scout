"""
Risk scoring - assesses danger levels of discovered sites.
"""

import re
import hashlib
from typing import Dict, List, Set, Tuple, Optional, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
import numpy as np

from src.utils.logger import get_logger

logger = get_logger(__name__)


class RiskLevel(Enum):
    """Risk levels for sites."""
    LOW = "low"          # Minimal risk
    MEDIUM = "medium"    # Some risk factors present
    HIGH = "high"        # Multiple risk factors
    CRITICAL = "critical" # Immediate danger


class RiskFactor(Enum):
    """Specific risk factors."""
    # Technical risks
    SUSPICIOUS_SSL = "suspicious_ssl"
    NO_SSL = "no_ssl"
    EXPIRED_CERT = "expired_cert"
    
    # Content risks
    ILLEGAL_CONTENT = "illegal_content"
    SUSPICIOUS_KEYWORDS = "suspicious_keywords"
    SCAM_INDICATORS = "scam_indicators"
    
    # Behavioral risks
    HONEYPOT_INDICATORS = "honeypot_indicators"
    MALWARE_INDICATORS = "malware_indicators"
    PHISHING_INDICATORS = "phishing_indicators"
    
    # Reputation risks
    KNOWN_BAD = "known_bad"
    RECENTLY_CREATED = "recently_created"
    SHORT_LIFESPAN = "short_lifespan"
    
    # Operational risks
    HIGH_TRAFFIC = "high_traffic"
    MULTIPLE_LOCATIONS = "multiple_locations"
    HIDDEN_OWNERSHIP = "hidden_ownership"


@dataclass
class RiskScore:
    """Comprehensive risk assessment."""
    level: RiskLevel
    score: float  # 0.0 to 1.0
    factors: List[RiskFactor]
    confidence: float = 0.8
    details: Dict[str, Any] = None
    assessed_at: datetime = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.assessed_at is None:
            self.assessed_at = datetime.now()
    
    @property
    def is_critical(self) -> bool:
        """Check if risk is critical."""
        return self.level == RiskLevel.CRITICAL
    
    @property
    def is_high(self) -> bool:
        """Check if risk is high or critical."""
        return self.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'level': self.level.value,
            'score': self.score,
            'factors': [f.value for f in self.factors],
            'confidence': self.confidence,
            'details': self.details,
            'assessed_at': self.assessed_at.isoformat(),
        }


class RiskScorer:
    """Assesses risk levels of dark web sites."""
    
    def __init__(self, known_bad_domains: Optional[Set[str]] = None):
        """Initialize risk scorer.
        
        Args:
            known_bad_domains: Set of known malicious domains
        """
        self.known_bad_domains = known_bad_domains or set()
        
        # Risk patterns
        self.scam_patterns = [
            r'\b(?:100%|guaranteed|free|instant|easy|fast|secret)\b',
            r'\b(?:million|billion|rich|wealth|fortune|profit)\b',
            r'\b(?:click here|buy now|order today|limited time)\b',
            r'\b(?:won.*lottery|inheritance|unclaimed.*money)\b',
            r'\b(?:double.*bitcoin|free.*bitcoin|bitcoin.*generator)\b',
        ]
        
        self.honeypot_patterns = [
            r'\b(?:login|signin|register|create.*account)\b',
            r'\b(?:verify.*human|captcha|security.*check)\b',
            r'\b(?:enter.*code|verification.*code|2fa)\b',
            r'<input[^>]*type="[^"]*password[^"]*"[^>]*>',
            r'<form[^>]*action="[^"]*login[^"]*"[^>]*>',
        ]
        
        self.phishing_patterns = [
            r'\b(?:update.*account|verify.*identity|security.*alert)\b',
            r'\b(?:suspended.*account|locked.*account|action.*required)\b',
            r'\b(?:confirm.*details|billing.*information|payment.*method)\b',
            r'phish|phishing|spoof',
        ]
        
        self.malware_patterns = [
            r'\b(?:crack|keygen|serial|patch|activator)\b',
            r'\b(?:free.*download|no.*survey|direct.*download)\b',
            r'\b(?:hack.*tool|exploit.*kit|rat.*builder)\b',
            r'\.exe\b|\.msi\b|\.bat\b|\.scr\b',
        ]
        
        # Compile patterns
        self.compiled_scam = [re.compile(p, re.IGNORECASE) for p in self.scam_patterns]
        self.compiled_honeypot = [re.compile(p, re.IGNORECASE) for p in self.honeypot_patterns]
        self.compiled_phishing = [re.compile(p, re.IGNORECASE) for p in self.phishing_patterns]
        self.compiled_malware = [re.compile(p, re.IGNORECASE) for p in self.malware_patterns]
        
        # Statistics
        self.stats = {
            'sites_assessed': 0,
            'critical_risks': 0,
            'high_risks': 0,
            'medium_risks': 0,
            'low_risks': 0,
        }
    
    def assess_risk(
        self,
        content: str,
        url: str,
        metadata: Optional[Dict[str, Any]] = None,
        classification: Optional[Dict[str, Any]] = None,
        safety_result: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """Assess risk of a site.
        
        Args:
            content: Site content
            url: Site URL
            metadata: Additional metadata
            classification: Classification results
            safety_result: Safety check results
            
        Returns:
            RiskScore with assessment
        """
        self.stats['sites_assessed'] += 1
        
        # Extract onion address
        onion_address = self._extract_onion_address(url)
        
        # Initialize factors and scores
        factors = []
        scores = []
        details = {}
        
        # 1. Check known bad domains
        if onion_address in self.known_bad_domains:
            factors.append(RiskFactor.KNOWN_BAD)
            scores.append(0.9)
            details['known_bad'] = True
        
        # 2. Check safety results
        if safety_result:
            if safety_result.get('action') == 'block':
                factors.append(RiskFactor.ILLEGAL_CONTENT)
                scores.append(1.0)
                details['illegal_content'] = True
            
            flagged_categories = safety_result.get('flagged_categories', [])
            if flagged_categories:
                factors.append(RiskFactor.SUSPICIOUS_KEYWORDS)
                scores.append(0.7)
                details['suspicious_keywords'] = flagged_categories
        
        # 3. Check scam indicators
        scam_score = self._check_patterns(content, self.compiled_scam)
        if scam_score > 0.5:
            factors.append(RiskFactor.SCAM_INDICATORS)
            scores.append(scam_score)
            details['scam_score'] = scam_score
        
        # 4. Check honeypot indicators
        honeypot_score = self._check_patterns(content, self.compiled_honeypot)
        if honeypot_score > 0.6:
            factors.append(RiskFactor.HONEYPOT_INDICATORS)
            scores.append(honeypot_score)
            details['honeypot_score'] = honeypot_score
        
        # 5. Check phishing indicators
        phishing_score = self._check_patterns(content, self.compiled_phishing)
        if phishing_score > 0.6:
            factors.append(RiskFactor.PHISHING_INDICATORS)
            scores.append(phishing_score)
            details['phishing_score'] = phishing_score
        
        # 6. Check malware indicators
        malware_score = self._check_patterns(content, self.compiled_malware)
        if malware_score > 0.5:
            factors.append(RiskFactor.MALWARE_INDICATORS)
            scores.append(malware_score)
            details['malware_score'] = malware_score
        
        # 7. Check SSL/TLS (if metadata available)
        if metadata:
            ssl_info = metadata.get('ssl', {})
            if not ssl_info.get('has_ssl', False):
                factors.append(RiskFactor.NO_SSL)
                scores.append(0.4)
                details['no_ssl'] = True
            elif ssl_info.get('expired', False):
                factors.append(RiskFactor.EXPIRED_CERT)
                scores.append(0.6)
                details['expired_cert'] = True
            elif ssl_info.get('self_signed', False):
                factors.append(RiskFactor.SUSPICIOUS_SSL)
                scores.append(0.5)
                details['self_signed'] = True
        
        # 8. Check domain age (if available)
        if metadata and metadata.get('first_seen'):
            first_seen = metadata['first_seen']
            if isinstance(first_seen, str):
                try:
                    first_seen_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    age_days = (datetime.now() - first_seen_dt).days
                    
                    if age_days < 7:
                        factors.append(RiskFactor.RECENTLY_CREATED)
                        scores.append(0.7)
                        details['recently_created'] = f"{age_days} days"
                    
                    if age_days < 30:
                        factors.append(RiskFactor.SHORT_LIFESPAN)
                        scores.append(0.5)
                        details['short_lifespan'] = f"{age_days} days"
                except (ValueError, TypeError):
                    pass
        
        # 9. Check classification
        if classification:
            category = classification.get('category')
            if category == 'scam':
                factors.append(RiskFactor.SCAM_INDICATORS)
                scores.append(0.8)
                details['classified_scam'] = True
            elif category == 'honeypot':
                factors.append(RiskFactor.HONEYPOT_INDICATORS)
                scores.append(0.9)
                details['classified_honeypot'] = True
        
        # Calculate overall score
        if scores:
            overall_score = np.mean(scores)
        else:
            overall_score = 0.1  # Default low risk
        
        # Determine risk level
        if overall_score >= 0.8:
            level = RiskLevel.CRITICAL
            self.stats['critical_risks'] += 1
        elif overall_score >= 0.6:
            level = RiskLevel.HIGH
            self.stats['high_risks'] += 1
        elif overall_score >= 0.4:
            level = RiskLevel.MEDIUM
            self.stats['medium_risks'] += 1
        else:
            level = RiskLevel.LOW
            self.stats['low_risks'] += 1
        
        # Calculate confidence
        confidence = self._calculate_confidence(factors, scores, content_length=len(content))
        
        return RiskScore(
            level=level,
            score=overall_score,
            factors=factors,
            confidence=confidence,
            details=details,
        )
    
    def _extract_onion_address(self, url: str) -> str:
        """Extract onion address from URL.
        
        Args:
            url: Full URL
            
        Returns:
            Onion address (hostname)
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or url
    
    def _check_patterns(self, text: str, patterns: List[re.Pattern]) -> float:
        """Check text against patterns.
        
        Args:
            text: Text to check
            patterns: Compiled regex patterns
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not text:
            return 0.0
        
        matches = 0
        for pattern in patterns:
            if pattern.search(text):
                matches += 1
        
        # Normalize score
        max_matches = len(patterns)
        if max_matches == 0:
            return 0.0
        
        score = matches / max_matches
        
        # Apply non-linear scaling (more matches = exponentially higher risk)
        return min(1.0, score * 1.5)
    
    def _calculate_confidence(
        self,
        factors: List[RiskFactor],
        scores: List[float],
        content_length: int,
    ) -> float:
        """Calculate confidence in risk assessment.
        
        Args:
            factors: Detected risk factors
            scores: Individual factor scores
            content_length: Length of analyzed content
            
        Returns:
            Confidence from 0.0 to 1.0
        """
        if not factors:
            return 0.3  # Low confidence when no factors found
        
        # Base confidence on number of factors
        factor_confidence = min(1.0, len(factors) / 10.0)
        
        # Adjust based on content length (more content = more reliable)
        content_confidence = min(1.0, content_length / 5000.0)
        
        # Adjust based on score consistency
        if scores:
            score_variance = np.var(scores) if len(scores) > 1 else 0.0
            consistency_confidence = 1.0 - min(1.0, score_variance * 2.0)
        else:
            consistency_confidence = 0.5
        
        # Combine confidences
        confidence = (factor_confidence * 0.4 + 
                     content_confidence * 0.3 + 
                     consistency_confidence * 0.3)
        
        return min(1.0, max(0.1, confidence))
    
    def add_known_bad_domain(self, domain: str):
        """Add a domain to known bad list.
        
        Args:
            domain: Onion address to mark as bad
        """
        self.known_bad_domains.add(domain)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get risk scorer statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['known_bad_domains'] = len(self.known_bad_domains)
        return stats


class ReputationTracker:
    """Tracks site reputation over time."""
    
    def __init__(self, history_days: int = 90):
        """Initialize reputation tracker.
        
        Args:
            history_days: Number of days to keep history
        """
        self.history_days = history_days
        self.reputation_history: Dict[str, List[Dict[str, Any]]] = {}
        
        # Reputation scores can change based on:
        # - Uptime/downtime
        # - Content changes
        # - User reports
        # - External intelligence
    
    def update_reputation(
        self,
        onion_address: str,
        risk_score: RiskScore,
        classification: Dict[str, Any],
        uptime: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Update reputation for a site.
        
        Args:
            onion_address: Site onion address
            risk_score: Current risk assessment
            classification: Current classification
            uptime: Uptime percentage (0.0-1.0)
            
        Returns:
            Current reputation score
        """
        if onion_address not in self.reputation_history:
            self.reputation_history[onion_address] = []
        
        # Create reputation entry
        entry = {
            'timestamp': datetime.now().isoformat(),
            'risk_level': risk_score.level.value,
            'risk_score': risk_score.score,
            'classification': classification,
            'uptime': uptime,
            'factors': [f.value for f in risk_score.factors],
        }
        
        # Add to history
        self.reputation_history[onion_address].append(entry)
        
        # Clean old entries
        self._clean_history(onion_address)
        
        # Calculate current reputation
        reputation = self._calculate_reputation(onion_address)
        
        return reputation
    
    def _clean_history(self, onion_address: str):
        """Clean old history entries.
        
        Args:
            onion_address: Site to clean history for
        """
        if onion_address not in self.reputation_history:
            return
        
        cutoff = datetime.now() - timedelta(days=self.history_days)
        cutoff_iso = cutoff.isoformat()
        
        # Keep only recent entries
        self.reputation_history[onion_address] = [
            entry for entry in self.reputation_history[onion_address]
            if entry['timestamp'] > cutoff_iso
        ]
    
    def _calculate_reputation(self, onion_address: str) -> Dict[str, Any]:
        """Calculate current reputation score.
        
        Args:
            onion_address: Site to calculate for
            
        Returns:
            Reputation dictionary
        """
        history = self.reputation_history.get(onion_address, [])
        
        if not history:
            return {
                'score': 0.5,  # Neutral
                'stability': 0.0,
                'trend': 'unknown',
                'history_count': 0,
            }
        
        # Calculate average risk score (inverted for reputation)
        risk_scores = [entry['risk_score'] for entry in history]
        avg_risk = np.mean(risk_scores)
        
        # Reputation is inverse of risk (0-1 scale)
        reputation_score = 1.0 - avg_risk
        
        # Calculate stability (consistency over time)
        if len(risk_scores) > 1:
            stability = 1.0 - np.std(risk_scores)
        else:
            stability = 0.5
        
        # Calculate trend
        if len(risk_scores) >= 3:
            recent = risk_scores[-3:]
            older = risk_scores[:-3] if len(risk_scores) > 3 else risk_scores[:1]
            
            recent_avg = np.mean(recent)
            older_avg = np.mean(older)
            
            if recent_avg < older_avg - 0.1:
                trend = 'improving'
            elif recent_avg > older_avg + 0.1:
                trend = 'worsening'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
        
        # Factor in uptime if available
        uptimes = [entry['uptime'] for entry in history if entry['uptime'] is not None]
        if uptimes:
            avg_uptime = np.mean(uptimes)
            # Weight reputation with uptime
            reputation_score = (reputation_score * 0.7) + (avg_uptime * 0.3)
        
        return {
            'score': min(1.0, max(0.0, reputation_score)),
            'stability': min(1.0, max(0.0, stability)),
            'trend': trend,
            'history_count': len(history),
            'last_assessment': history[-1]['timestamp'],
        }
    
    def get_reputation(self, onion_address: str) -> Optional[Dict[str, Any]]:
        """Get current reputation for a site.
        
        Args:
            onion_address: Site to get reputation for
            
        Returns:
            Reputation dictionary or None
        """
        if onion_address not in self.reputation_history:
            return None
        
        return self._calculate_reputation(onion_address)
    
    def get_history(self, onion_address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get reputation history for a site.
        
        Args:
            onion_address: Site to get history for
            limit: Maximum number of entries to return
            
        Returns:
            List of history entries
        """
        history = self.reputation_history.get(onion_address, [])
        return history[-limit:] if limit else history