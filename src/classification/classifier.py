"""
Classification engine - categorizes dark web sites.
"""

import re
import json
from typing import Dict, List, Set, Tuple, Optional, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import hashlib
import numpy as np
from collections import Counter

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SiteCategory(Enum):
    """Categories for dark web sites."""
    FORUM = "forum"               # Discussion forums
    MARKET = "market"             # Marketplace for goods/services
    SERVICE = "service"           # Hosting, mixing, etc.
    LIBRARY = "library"           # Document/ebook repositories
    BLOG = "blog"                 # Personal or group blogs
    MIRROR = "mirror"             # Mirrors of other sites
    HIDDEN_SERVICE = "hidden_service"  # General hidden service
    CHAT = "chat"                 # Chat rooms/messaging
    SCAM = "scam"                 # Scam/fraud sites
    HONEYPOT = "honeypot"         # Law enforcement honeypot
    OTHER = "other"               # Uncategorized


@dataclass
class ClassificationResult:
    """Result of site classification."""
    category: SiteCategory
    confidence: float
    subcategory: Optional[str] = None
    features: Dict[str, Any] = None
    model_version: str = "1.0"
    processed_at: datetime = None
    
    def __post_init__(self):
        if self.features is None:
            self.features = {}
        if self.processed_at is None:
            self.processed_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'category': self.category.value,
            'confidence': self.confidence,
            'subcategory': self.subcategory,
            'features': self.features,
            'model_version': self.model_version,
            'processed_at': self.processed_at.isoformat(),
        }


class RuleBasedClassifier:
    """Rule-based classifier for dark web sites."""
    
    def __init__(self, rules_file: Optional[str] = None):
        """Initialize classifier with rules.
        
        Args:
            rules_file: Path to JSON file with classification rules
        """
        self.rules = self._load_rules(rules_file)
        self.compiled_rules = self._compile_rules()
        
        # Statistics
        self.stats = {
            'classifications': 0,
            'rule_hits': {},
            'fallback_count': 0,
        }
    
    def _load_rules(self, rules_file: Optional[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Load classification rules from file.
        
        Args:
            rules_file: Path to rules file
            
        Returns:
            Dictionary of category -> rules
        """
        default_rules = {
            SiteCategory.FORUM.value: [
                {
                    'patterns': [
                        r'\b(?:forum|board|discussion|thread|post|topic)\b',
                        r'\b(?:register|login|members|user|profile)\b',
                        r'\b(?:category|section|subforum)\b',
                    ],
                    'weight': 0.8,
                    'min_matches': 2,
                },
                {
                    'patterns': [
                        r'<form[^>]*action="[^"]*post[^"]*"',
                        r'<div[^>]*class="[^"]*thread[^"]*"',
                        r'<a[^>]*href="[^"]*viewforum[^"]*"',
                    ],
                    'weight': 0.9,
                    'min_matches': 1,
                },
            ],
            SiteCategory.MARKET.value: [
                {
                    'patterns': [
                        r'\b(?:market|shop|store|vendor|product|item|listing)\b',
                        r'\b(?:price|cost|usd|btc|bitcoin|payment)\b',
                        r'\b(?:cart|checkout|purchase|buy|sell|order)\b',
                    ],
                    'weight': 0.85,
                    'min_matches': 2,
                },
                {
                    'patterns': [
                        r'<form[^>]*action="[^"]*cart[^"]*"',
                        r'<div[^>]*class="[^"]*product[^"]*"',
                        r'\$\d+(?:\.\d{2})?',  # Price patterns
                    ],
                    'weight': 0.9,
                    'min_matches': 1,
                },
            ],
            SiteCategory.SERVICE.value: [
                {
                    'patterns': [
                        r'\b(?:service|hosting|vpn|proxy|mixer|tumbler)\b',
                        r'\b(?:secure|private|anonymous|encrypted)\b',
                        r'\b(?:price|plan|subscription|monthly|yearly)\b',
                    ],
                    'weight': 0.7,
                    'min_matches': 2,
                },
            ],
            SiteCategory.LIBRARY.value: [
                {
                    'patterns': [
                        r'\b(?:library|archive|collection|repository)\b',
                        r'\b(?:book|document|paper|article|publication)\b',
                        r'\b(?:download|pdf|epub|mobi|torrent)\b',
                    ],
                    'weight': 0.8,
                    'min_matches': 2,
                },
                {
                    'patterns': [
                        r'<a[^>]*href="[^"]*\.(?:pdf|epub|mobi|docx?)[^"]*"',
                        r'<div[^>]*class="[^"]*book[^"]*"',
                    ],
                    'weight': 0.9,
                    'min_matches': 1,
                },
            ],
            SiteCategory.BLOG.value: [
                {
                    'patterns': [
                        r'\b(?:blog|post|article|entry|update)\b',
                        r'\b(?:author|writer|posted|published|date)\b',
                        r'\b(?:comment|reply|feedback)\b',
                    ],
                    'weight': 0.75,
                    'min_matches': 2,
                },
                {
                    'patterns': [
                        r'<div[^>]*class="[^"]*post[^"]*"',
                        r'<time[^>]*datetime="[^"]*"',
                    ],
                    'weight': 0.8,
                    'min_matches': 1,
                },
            ],
            SiteCategory.CHAT.value: [
                {
                    'patterns': [
                        r'\b(?:chat|message|room|channel|conversation)\b',
                        r'\b(?:online|users|connected|disconnected)\b',
                        r'\b(?:send|receive|type|enter|join)\b',
                    ],
                    'weight': 0.8,
                    'min_matches': 2,
                },
            ],
            SiteCategory.SCAM.value: [
                {
                    'patterns': [
                        r'\b(?:free|easy|fast|guaranteed|100%|legit)\b',
                        r'\b(?:million|billion|rich|wealth|fortune)\b',
                        r'\b(?:limited|offer|discount|bonus|extra)\b',
                        r'\b(?:click here|buy now|order today)\b',
                    ],
                    'weight': 0.6,
                    'min_matches': 3,
                    'scam_indicators': True,
                },
                {
                    'patterns': [
                        r'bitcoin.*address.*send',
                        r'wallet.*recovery.*service',
                        r'hack.*password.*recovery',
                    ],
                    'weight': 0.9,
                    'min_matches': 1,
                    'scam_indicators': True,
                },
            ],
            SiteCategory.HONEYPOT.value: [
                {
                    'patterns': [
                        r'\b(?:login|signin|authentication|verify)\b',
                        r'\b(?:captcha|security|check|human)\b',
                        r'\b(?:please|enter|submit|continue)\b',
                    ],
                    'weight': 0.5,
                    'min_matches': 2,
                    'honeypot_indicators': True,
                },
            ],
        }
        
        if rules_file:
            try:
                with open(rules_file, 'r') as f:
                    custom_rules = json.load(f)
                # Merge with defaults
                for category, rules in custom_rules.items():
                    if category in default_rules:
                        default_rules[category].extend(rules)
                    else:
                        default_rules[category] = rules
            except Exception as e:
                logger.error(f"Failed to load rules file: {e}")
        
        return default_rules
    
    def _compile_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Compile regex patterns for efficiency.
        
        Returns:
            Dictionary of compiled rules
        """
        compiled_rules = {}
        
        for category, rules in self.rules.items():
            compiled_category_rules = []
            
            for rule in rules:
                compiled_rule = rule.copy()
                compiled_rule['compiled_patterns'] = [
                    re.compile(pattern, re.IGNORECASE | re.UNICODE)
                    for pattern in rule['patterns']
                ]
                compiled_category_rules.append(compiled_rule)
            
            compiled_rules[category] = compiled_category_rules
        
        return compiled_rules
    
    def classify(
        self,
        text: str,
        url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ClassificationResult:
        """Classify site based on text content.
        
        Args:
            text: Text content to analyze
            url: Site URL for additional context
            metadata: Additional metadata
            
        Returns:
            ClassificationResult
        """
        self.stats['classifications'] += 1
        
        # Extract features
        features = self._extract_features(text, url, metadata)
        
        # Apply rules
        scores = self._apply_rules(text, features)
        
        # Determine category
        if scores:
            best_category = max(scores.items(), key=lambda x: x[1]['score'])
            category_name, category_data = best_category
            
            # Check if we should override with scam/honeypot detection
            scam_score = scores.get(SiteCategory.SCAM.value, {}).get('score', 0)
            honeypot_score = scores.get(SiteCategory.HONEYPOT.value, {}).get('score', 0)
            
            if scam_score > 0.8:
                final_category = SiteCategory.SCAM
                confidence = scam_score
                subcategory = "probable_scam"
            elif honeypot_score > 0.7:
                final_category = SiteCategory.HONEYPOT
                confidence = honeypot_score
                subcategory = "probable_honeypot"
            else:
                final_category = SiteCategory(category_name)
                confidence = category_data['score']
                subcategory = category_data.get('subcategory')
            
            # Update rule hit statistics
            if category_name in self.stats['rule_hits']:
                self.stats['rule_hits'][category_name] += 1
            else:
                self.stats['rule_hits'][category_name] = 1
        else:
            # Fallback to hidden_service
            final_category = SiteCategory.HIDDEN_SERVICE
            confidence = 0.3
            subcategory = "uncategorized"
            self.stats['fallback_count'] += 1
        
        return ClassificationResult(
            category=final_category,
            confidence=confidence,
            subcategory=subcategory,
            features=features,
            model_version="rule_based_1.0",
        )
    
    def _extract_features(
        self,
        text: str,
        url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Extract features from text and metadata.
        
        Args:
            text: Text content
            url: Site URL
            metadata: Additional metadata
            
        Returns:
            Dictionary of features
        """
        features = {
            'text_length': len(text),
            'word_count': len(text.split()),
            'url_length': len(url) if url else 0,
            'has_login_form': False,
            'has_search_form': False,
            'has_cart': False,
            'has_forum_elements': False,
            'has_blog_elements': False,
            'price_mentions': 0,
            'bitcoin_mentions': 0,
            'contact_forms': 0,
        }
        
        # Check for forms
        if '<form' in text.lower():
            forms_lower = text.lower()
            if 'login' in forms_lower or 'password' in forms_lower:
                features['has_login_form'] = True
            if 'search' in forms_lower:
                features['has_search_form'] = True
            if 'cart' in forms_lower or 'checkout' in forms_lower:
                features['has_cart'] = True
        
        # Check for forum elements
        forum_patterns = [
            r'viewforum\.php',
            r'showthread\.php',
            r'post\.php',
            r'forumdisplay\.php',
        ]
        for pattern in forum_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                features['has_forum_elements'] = True
                break
        
        # Check for blog elements
        blog_patterns = [
            r'<article',
            r'<time[^>]*datetime=',
            r'posted on',
            r'published on',
        ]
        for pattern in blog_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                features['has_blog_elements'] = True
                break
        
        # Count price mentions
        price_patterns = [
            r'\$\d+(?:\.\d{2})?',
            r'\d+\s*(?:usd|eur|gbp|btc)',
            r'price:\s*\d+',
        ]
        for pattern in price_patterns:
            features['price_mentions'] += len(re.findall(pattern, text, re.IGNORECASE))
        
        # Count Bitcoin mentions
        bitcoin_patterns = [
            r'bitcoin',
            r'btc',
            r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Bitcoin address pattern
        ]
        for pattern in bitcoin_patterns:
            features['bitcoin_mentions'] += len(re.findall(pattern, text, re.IGNORECASE))
        
        # Count contact forms
        contact_patterns = [
            r'contact us',
            r'get in touch',
            r'email us',
            r'<a[^>]*href="mailto:',
        ]
        for pattern in contact_patterns:
            features['contact_forms'] += len(re.findall(pattern, text, re.IGNORECASE))
        
        # Add metadata if available
        if metadata:
            features.update({
                f'metadata_{k}': v for k, v in metadata.items()
                if isinstance(v, (str, int, float, bool))
            })
        
        return features
    
    def _apply_rules(self, text: str, features: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Apply classification rules to text.
        
        Args:
            text: Text content
            features: Extracted features
            
        Returns:
            Dictionary of category -> score data
        """
        scores = {}
        
        for category_name, rules in self.compiled_rules.items():
            category_scores = []
            matched_rules = []
            
            for rule in rules:
                matches = 0
                
                # Check each pattern
                for pattern in rule['compiled_patterns']:
                    if pattern.search(text):
                        matches += 1
                
                # Check if we have enough matches
                if matches >= rule.get('min_matches', 1):
                    # Calculate score based on matches
                    base_score = rule.get('weight', 0.5)
                    match_ratio = matches / len(rule['compiled_patterns'])
                    score = base_score * (0.5 + 0.5 * match_ratio)
                    
                    category_scores.append(score)
                    matched_rules.append({
                        'rule': rule.get('description', 'unnamed_rule'),
                        'score': score,
                        'matches': matches,
                    })
            
            if category_scores:
                # Use maximum score from matched rules
                max_score = max(category_scores)
                
                # Adjust score based on features
                feature_adjustment = self._calculate_feature_adjustment(category_name, features)
                final_score = min(1.0, max_score + feature_adjustment)
                
                scores[category_name] = {
                    'score': final_score,
                    'matched_rules': matched_rules,
                    'subcategory': self._determine_subcategory(category_name, features, matched_rules),
                }
        
        return scores
    
    def _calculate_feature_adjustment(self, category: str, features: Dict[str, Any]) -> float:
        """Calculate score adjustment based on features.
        
        Args:
            category: Category name
            features: Extracted features
            
        Returns:
            Score adjustment (-0.3 to +0.3)
        """
        adjustment = 0.0
        
        if category == SiteCategory.FORUM.value:
            if features['has_forum_elements']:
                adjustment += 0.2
            if features['has_login_form']:
                adjustment += 0.1
        
        elif category == SiteCategory.MARKET.value:
            if features['has_cart']:
                adjustment += 0.2
            if features['price_mentions'] > 0:
                adjustment += 0.1 * min(3, features['price_mentions'])
        
        elif category == SiteCategory.SERVICE.value:
            if features['bitcoin_mentions'] > 0:
                adjustment += 0.1 * min(3, features['bitcoin_mentions'])
        
        elif category == SiteCategory.LIBRARY.value:
            if features['text_length'] > 10000:
                adjustment += 0.1
        
        elif category == SiteCategory.BLOG.value:
            if features['has_blog_elements']:
                adjustment += 0.2
        
        # Penalize if wrong features are present
        if category != SiteCategory.MARKET.value and features['has_cart']:
            adjustment -= 0.1
        
        if category != SiteCategory.FORUM.value and features['has_forum_elements']:
            adjustment -= 0.1
        
        return max(-0.3, min(0.3, adjustment))
    
    def _determine_subcategory(
        self,
        category: str,
        features: Dict[str, Any],
        matched_rules: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Determine subcategory based on features and matched rules.
        
        Args:
            category: Main category
            features: Extracted features
            matched_rules: Matched rules
            
        Returns:
            Subcategory string or None
        """
        if category == SiteCategory.FORUM.value:
            if features['price_mentions'] > 0:
                return "marketplace_forum"
            elif features['bitcoin_mentions'] > 0:
                return "crypto_forum"
            else:
                return "general_forum"
        
        elif category == SiteCategory.MARKET.value:
            if features['bitcoin_mentions'] > 5:
                return "crypto_market"
            else:
                return "general_market"
        
        elif category == SiteCategory.SERVICE.value:
            if any('vpn' in rule['rule'].lower() for rule in matched_rules):
                return "vpn_service"
            elif any('mixer' in rule['rule'].lower() for rule in matched_rules):
                return "mixer_service"
            else:
                return "general_service"
        
        elif category == SiteCategory.LIBRARY.value:
            if features['word_count'] > 100000:
                return "large_library"
            else:
                return "small_library"
        
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get classifier statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['total_classifications'] = self.stats['classifications']
        return stats