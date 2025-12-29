"""
Safety filter - prevents processing of illegal content while maintaining privacy.
"""

import re
import hashlib
import json
import base64
from typing import Dict, List, Set, Tuple, Optional, Any
from enum import Enum
import io
from dataclasses import dataclass
import mmh3  # For fast hashing
from PIL import Image, UnidentifiedImageError
import numpy as np

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SafetyAction(Enum):
    """Action to take based on safety check."""
    ALLOW = "allow"           # Content is safe
    BLOCK = "block"           # Content is illegal/unsafe
    REVIEW = "review"         # Needs human review
    QUARANTINE = "quarantine" # Isolate for further analysis


class ContentType(Enum):
    """Type of content being checked."""
    TEXT = "text"
    HTML = "html"
    IMAGE = "image"
    PDF = "pdf"
    BINARY = "binary"
    UNKNOWN = "unknown"


@dataclass
class SafetyResult:
    """Result of safety checking."""
    action: SafetyAction
    confidence: float = 1.0
    flagged_categories: List[str] = None
    risk_factors: List[str] = None
    reason: Optional[str] = None
    content_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.flagged_categories is None:
            self.flagged_categories = []
        if self.risk_factors is None:
            self.risk_factors = []
    
    @property
    def is_safe(self) -> bool:
        """Check if content is safe to process."""
        return self.action in [SafetyAction.ALLOW, SafetyAction.REVIEW]


class IllegalContentDetector:
    """Detects illegal content patterns."""
    
    def __init__(self, patterns_file: Optional[str] = None):
        """Initialize detector with illegal patterns.
        
        Args:
            patterns_file: Path to JSON file with illegal patterns
        """
        self.patterns = self._load_patterns(patterns_file)
        self.compiled_patterns = self._compile_patterns()
        
        # Known illegal content hashes (from international databases)
        # In production, this would be loaded from secure, encrypted storage
        self.illegal_hashes: Set[str] = set()
        
        # Statistics
        self.stats = {
            'checks_performed': 0,
            'content_blocked': 0,
            'content_flagged': 0,
            'false_positives': 0,
        }
    
    def _load_patterns(self, patterns_file: Optional[str]) -> Dict[str, List[str]]:
        """Load illegal patterns from file.
        
        Args:
            patterns_file: Path to patterns file
            
        Returns:
            Dictionary of category -> patterns
        """
        default_patterns = {
            'child_exploitation': [
                r'\b(?:child|minor|underage|juvenile).{0,20}(?:abuse|exploit|porn|sex|nude)\b',
                r'\b(?:cp|loli|shota|csam)\b',
                r'\b(?:pre.?teen|tween|young.{0,10}girl|boy)\b',
            ],
            'violence_gore': [
                r'\b(?:snuff|real.{0,10}death|murder.{0,10}video|torture.{0,10}video)\b',
                r'\b(?:gore|graphic.{0,10}violence|brutal.{0,10}attack)\b',
                r'\b(?:human.{0,10}trafficking|organ.{0,10}harvesting)\b',
            ],
            'weapons_explosives': [
                r'\b(?:weapon.{0,10}sale|gun.{0,10}market|firearm.{0,10}trade)\b',
                r'\b(?:explosive.{0,10}recipe|bomb.{0,10}making|detonator)\b',
                r'\b(?:chemical.{0,10}weapon|bioweapon|nerve.{0,10}agent)\b',
            ],
            'drugs_narcotics': [
                r'\b(?:drug.{0,10}market|opioid.{0,10}sale|fentanyl.{0,10}purchase)\b',
                r'\b(?:silk.{0,10}road|dark.{0,10}market|drug.{0,10}vendor)\b',
                r'\b(?:cocaine|heroin|methamphetamine|mdma).{0,10}(?:sale|buy|vendor)\b',
            ],
            'fraud_services': [
                r'\b(?:credit.{0,10}card.{0,10}fraud|identity.{0,10}theft|bank.{0,10}login)\b',
                r'\b(?:ddos.{0,10}service|hack.{0,10}for.{0,10}hire|ransomware.{0,10}as.{0,10}service)\b',
                r'\b(?:counterfeit.{0,10}money|fake.{0,10}id|forged.{0,10}documents)\b',
            ],
            'hate_speech': [
                r'\b(?:racial.{0,10}slur|hate.{0,10}group|extremist.{0,10}propaganda)\b',
                r'\b(?:genocide.{0,10}promotion|ethnic.{0,10}cleansing|racial.{0,10}supremacy)\b',
            ],
        }
        
        if patterns_file:
            try:
                with open(patterns_file, 'r') as f:
                    custom_patterns = json.load(f)
                # Merge with defaults
                for category, patterns in custom_patterns.items():
                    if category in default_patterns:
                        default_patterns[category].extend(patterns)
                    else:
                        default_patterns[category] = patterns
            except Exception as e:
                logger.error(f"Failed to load patterns file: {e}")
        
        return default_patterns
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for efficiency.
        
        Returns:
            Dictionary of compiled patterns
        """
        compiled = {}
        for category, patterns in self.patterns.items():
            compiled[category] = [
                re.compile(pattern, re.IGNORECASE | re.UNICODE) 
                for pattern in patterns
            ]
        return compiled
    
    def check_text(self, text: str, content_type: ContentType = ContentType.TEXT) -> SafetyResult:
        """Check text content for illegal patterns.
        
        Args:
            text: Text to check
            content_type: Type of content
            
        Returns:
            SafetyResult with action and details
        """
        self.stats['checks_performed'] += 1
        
        # Calculate content hash (for deduplication)
        content_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
        
        # Check against known illegal hashes
        if content_hash in self.illegal_hashes:
            return SafetyResult(
                action=SafetyAction.BLOCK,
                confidence=1.0,
                flagged_categories=['known_illegal_hash'],
                risk_factors=['hash_match'],
                reason="Content matches known illegal material hash",
                content_hash=content_hash,
            )
        
        flagged_categories = []
        risk_factors = []
        
        # Check each category
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    flagged_categories.append(category)
                    
                    # Extract risk factors (context around match)
                    matches = pattern.finditer(text)
                    for match in list(matches)[:3]:  # Limit to first 3 matches
                        start = max(0, match.start() - 20)
                        end = min(len(text), match.end() + 20)
                        context = text[start:end].replace('\n', ' ').strip()
                        risk_factors.append(f"{category}: {context}")
                    
                    break  # Stop checking this category after first match
        
        # Determine action based on severity
        if any(cat in ['child_exploitation', 'violence_gore'] for cat in flagged_categories):
            action = SafetyAction.BLOCK
            confidence = 0.95
            self.stats['content_blocked'] += 1
        elif flagged_categories:
            action = SafetyAction.REVIEW
            confidence = 0.7
            self.stats['content_flagged'] += 1
        else:
            action = SafetyAction.ALLOW
            confidence = 0.9
        
        return SafetyResult(
            action=action,
            confidence=confidence,
            flagged_categories=flagged_categories,
            risk_factors=risk_factors[:5],  # Limit risk factors
            content_hash=content_hash,
        )
    
    def check_image(self, image_bytes: bytes) -> SafetyResult:
        """Check image content for illegal material.
        
        Note: We use perceptual hashing and metadata only.
        We NEVER analyze image content directly.
        
        Args:
            image_bytes: Image bytes to check
            
        Returns:
            SafetyResult with action and details
        """
        self.stats['checks_performed'] += 1
        
        try:
            # Calculate hashes
            md5_hash = hashlib.md5(image_bytes).hexdigest()
            sha256_hash = hashlib.sha256(image_bytes).hexdigest()
            
            # Check against known illegal hashes
            if md5_hash in self.illegal_hashes or sha256_hash in self.illegal_hashes:
                return SafetyResult(
                    action=SafetyAction.BLOCK,
                    confidence=0.99,
                    flagged_categories=['known_illegal_image'],
                    risk_factors=['hash_match'],
                    reason="Image matches known illegal material hash",
                    content_hash=sha256_hash,
                )
            
            # Calculate perceptual hash (for similar image detection)
            try:
                image = Image.open(io.BytesIO(image_bytes))
                
                # Convert to grayscale and resize for hashing
                image_gray = image.convert('L').resize((32, 32), Image.Resampling.LANCZOS)
                
                # Calculate average pixel value
                pixels = list(image_gray.getdata())
                avg = sum(pixels) / len(pixels)
                
                # Create hash (1 if pixel > average, else 0)
                phash = ''.join('1' if pixel > avg else '0' for pixel in pixels)
                
                # Convert to hex
                phash_hex = hex(int(phash, 2))[2:].zfill(32)
                
                # In production, we'd check against database of known illegal perceptual hashes
                # For now, we just store it
                
            except UnidentifiedImageError:
                # Not a valid image
                return SafetyResult(
                    action=SafetyAction.ALLOW,
                    confidence=0.5,
                    flagged_categories=['invalid_image'],
                    reason="Invalid image format",
                    content_hash=sha256_hash,
                )
            
            # Check image metadata for suspicious patterns
            risk_factors = []
            
            try:
                # Extract basic metadata
                width, height = image.size
                format = image.format
                mode = image.mode
                
                # Check for suspicious characteristics
                if width < 50 or height < 50:
                    risk_factors.append("very_small_image")
                
                if format in ['GIF', 'MPO']:  # Multi-image formats
                    risk_factors.append("multi_frame_format")
                
                # Check file size vs dimensions ratio (very small file for large dimensions)
                file_size = len(image_bytes)
                pixel_count = width * height
                if pixel_count > 1000000 and file_size < 10000:  # 1MP image < 10KB
                    risk_factors.append("suspicious_compression")
            
            except Exception:
                pass
            
            if risk_factors:
                return SafetyResult(
                    action=SafetyAction.REVIEW,
                    confidence=0.6,
                    flagged_categories=['suspicious_image'],
                    risk_factors=risk_factors,
                    content_hash=sha256_hash,
                )
            
            return SafetyResult(
                action=SafetyAction.ALLOW,
                confidence=0.8,
                content_hash=sha256_hash,
            )
            
        except Exception as e:
            logger.error(f"Error checking image: {e}")
            return SafetyResult(
                action=SafetyAction.REVIEW,
                confidence=0.3,
                flagged_categories=['check_failed'],
                risk_factors=[f"error: {str(e)[:100]}"],
                content_hash=hashlib.sha256(image_bytes).hexdigest() if image_bytes else None,
            )
    
    def check_binary(self, data: bytes, mime_type: Optional[str] = None) -> SafetyResult:
        """Check binary data for illegal content.
        
        Args:
            data: Binary data to check
            mime_type: Optional MIME type hint
            
        Returns:
            SafetyResult with action and details
        """
        self.stats['checks_performed'] += 1
        
        content_hash = hashlib.sha256(data).hexdigest()
        
        # Check against known illegal hashes
        if content_hash in self.illegal_hashes:
            return SafetyResult(
                action=SafetyAction.BLOCK,
                confidence=0.99,
                flagged_categories=['known_illegal_binary'],
                risk_factors=['hash_match'],
                reason="Binary data matches known illegal material hash",
                content_hash=content_hash,
            )
        
        # Check based on MIME type
        risk_factors = []
        
        if mime_type:
            suspicious_types = [
                'application/x-executable',
                'application/x-msdownload',
                'application/vnd.microsoft.portable-executable',
                'application/x-dosexec',
            ]
            
            if any(susp in mime_type.lower() for susp in suspicious_types):
                risk_factors.append(f"suspicious_mime_type: {mime_type}")
        
        # Check for common exploit patterns in first 1KB
        if len(data) > 1024:
            header = data[:1024]
            
            # Check for PE header (Windows executable)
            if header.startswith(b'MZ'):
                risk_factors.append("windows_executable")
            
            # Check for ELF header (Linux executable)
            if header.startswith(b'\x7fELF'):
                risk_factors.append("linux_executable")
            
            # Check for shellcode patterns
            shellcode_patterns = [
                b'\xcc' * 10,  # INT3 instructions (debugger traps)
                b'\x90' * 20,  # NOP sled
            ]
            
            for pattern in shellcode_patterns:
                if pattern in header:
                    risk_factors.append("possible_shellcode")
                    break
        
        if risk_factors:
            return SafetyResult(
                action=SafetyAction.REVIEW,
                confidence=0.7,
                flagged_categories=['suspicious_binary'],
                risk_factors=risk_factors,
                content_hash=content_hash,
            )
        
        return SafetyResult(
            action=SafetyAction.ALLOW,
            confidence=0.6,
            content_hash=content_hash,
        )
    
    def add_illegal_hash(self, content_hash: str):
        """Add a hash to the illegal content database.
        
        Args:
            content_hash: SHA256 hash of illegal content
        """
        self.illegal_hashes.add(content_hash)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        return self.stats.copy()


class SafeContentProcessor:
    """Processes content safely with multiple protection layers."""
    
    def __init__(
        self,
        detector: Optional[IllegalContentDetector] = None,
        max_text_size: int = 10 * 1024 * 1024,  # 10MB
        max_image_size: int = 5 * 1024 * 1024,   # 5MB
        max_binary_size: int = 20 * 1024 * 1024, # 20MB
        air_gap_mode: bool = True,
    ):
        """Initialize safe content processor.
        
        Args:
            detector: Illegal content detector
            max_text_size: Maximum text size to process
            max_image_size: Maximum image size to process
            max_binary_size: Maximum binary size to process
            air_gap_mode: Whether to run in air-gapped mode
        """
        self.detector = detector or IllegalContentDetector()
        self.max_text_size = max_text_size
        self.max_image_size = max_image_size
        self.max_binary_size = max_binary_size
        self.air_gap_mode = air_gap_mode
        
        # Content type detection
        self.mime_patterns = {
            'text/html': re.compile(r'<html|<head|<body|<!DOCTYPE html', re.IGNORECASE),
            'image/jpeg': re.compile(b'^\xff\xd8\xff'),
            'image/png': re.compile(b'^\x89PNG\r\n\x1a\n'),
            'image/gif': re.compile(b'^GIF8[79]a'),
            'application/pdf': re.compile(b'^%PDF'),
        }
    
    def process_content(
        self,
        content: Any,
        content_type_hint: Optional[str] = None,
        url: Optional[str] = None,
    ) -> Tuple[SafetyResult, Optional[str]]:
        """Process content safely.
        
        Args:
            content: Content to process (str, bytes, etc.)
            content_type_hint: Optional content type hint
            url: Source URL (for logging)
            
        Returns:
            Tuple of (SafetyResult, processed_content_or_none)
            Returns None for processed content if blocked or in air-gap mode
        """
        # Determine content type
        content_type, processed = self._normalize_content(content, content_type_hint)
        
        if processed is None:
            return SafetyResult(
                action=SafetyAction.BLOCK,
                confidence=1.0,
                flagged_categories=['invalid_content'],
                reason="Failed to normalize content",
            ), None
        
        # Check size limits
        size_check = self._check_size(processed, content_type)
        if not size_check.is_safe:
            return size_check, None
        
        # Perform safety check based on content type
        if content_type == ContentType.TEXT or content_type == ContentType.HTML:
            safety_result = self.detector.check_text(processed, content_type)
        elif content_type == ContentType.IMAGE:
            safety_result = self.detector.check_image(processed)
        else:
            safety_result = self.detector.check_binary(processed, str(content_type))
        
        # In air-gap mode, we don't return the actual content
        # We only return metadata for safe processing
        if self.air_gap_mode or not safety_result.is_safe:
            return safety_result, None
        
        return safety_result, processed
    
    def _normalize_content(self, content: Any, content_type_hint: Optional[str]) -> Tuple[ContentType, Optional[bytes]]:
        """Normalize content to bytes and detect type.
        
        Args:
            content: Content to normalize
            content_type_hint: Optional content type hint
            
        Returns:
            Tuple of (ContentType, normalized_bytes)
        """
        if isinstance(content, str):
            return ContentType.TEXT, content.encode('utf-8')
        elif isinstance(content, bytes):
            # Try to detect type
            detected_type = self._detect_content_type(content, content_type_hint)
            return detected_type, content
        else:
            # Convert to string then bytes
            try:
                content_str = str(content)
                return ContentType.TEXT, content_str.encode('utf-8')
            except Exception:
                return ContentType.UNKNOWN, None
    
    def _detect_content_type(self, data: bytes, hint: Optional[str]) -> ContentType:
        """Detect content type from bytes.
        
        Args:
            data: Content bytes
            hint: Optional MIME type hint
            
        Returns:
            ContentType enum
        """
        if hint:
            hint_lower = hint.lower()
            if 'html' in hint_lower:
                return ContentType.HTML
            elif 'image' in hint_lower:
                return ContentType.IMAGE
            elif 'pdf' in hint_lower:
                return ContentType.PDF
            elif 'text' in hint_lower:
                return ContentType.TEXT
        
        # Check magic bytes
        for mime_type, pattern in self.mime_patterns.items():
            if len(data) >= 10 and pattern.match(data[:10]):
                if 'image' in mime_type:
                    return ContentType.IMAGE
                elif 'html' in mime_type:
                    return ContentType.HTML
                elif 'pdf' in mime_type:
                    return ContentType.PDF
        
        # Try to decode as text
        try:
            data.decode('utf-8')
            # Check if it looks like HTML
            if b'<' in data and (b'html' in data.lower() or b'body' in data.lower()):
                return ContentType.HTML
            return ContentType.TEXT
        except UnicodeDecodeError:
            # Check if it's an image by trying to open it
            try:
                Image.open(io.BytesIO(data[:100]))  # Just check header
                return ContentType.IMAGE
            except Exception:
                pass
        
        return ContentType.BINARY
    
    def _check_size(self, data: bytes, content_type: ContentType) -> SafetyResult:
        """Check if content size is within limits.
        
        Args:
            data: Content bytes
            content_type: Type of content
            
        Returns:
            SafetyResult
        """
        size = len(data)
        
        if content_type in [ContentType.TEXT, ContentType.HTML]:
            max_size = self.max_text_size
            size_type = "text"
        elif content_type == ContentType.IMAGE:
            max_size = self.max_image_size
            size_type = "image"
        else:
            max_size = self.max_binary_size
            size_type = "binary"
        
        if size > max_size:
            return SafetyResult(
                action=SafetyAction.BLOCK,
                confidence=0.9,
                flagged_categories=['size_exceeded'],
                risk_factors=[f"{size_type}_size_{size}_exceeds_{max_size}"],
                reason=f"{size_type.capitalize()} size {size} exceeds limit {max_size}",
            )
        
        return SafetyResult(
            action=SafetyAction.ALLOW,
            confidence=1.0,
        )
    
    def sanitize_text(self, text: str, keep_structure: bool = True) -> str:
        """Sanitize text for safe viewing/analysis.
        
        Args:
            text: Text to sanitize
            keep_structure: Whether to keep HTML structure
            
        Returns:
            Sanitized text
        """
        if not keep_structure:
            # Remove all HTML tags
            text = re.sub(r'<[^>]+>', ' ', text)
        
        # Remove script and style tags with content
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove event handlers
        text = re.sub(r'\bon\w+="[^"]*"', '', text, flags=re.IGNORECASE)
        text = re.sub(r"\bon\w+='[^']*'", '', text, flags=re.IGNORECASE)
        
        # Remove JavaScript URLs
        text = re.sub(r'\bhref="javascript:[^"]*"', 'href="#"', text, flags=re.IGNORECASE)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    
    def extract_safe_features(self, content: str, content_type: ContentType) -> Dict[str, Any]:
        """Extract safe features from content (no illegal material).
        
        Args:
            content: Content to analyze
            content_type: Type of content
            
        Returns:
            Dictionary of safe features
        """
        features = {
            'content_type': content_type.value,
            'size_bytes': len(content) if isinstance(content, bytes) else len(content.encode('utf-8')),
            'timestamp': None,  # Would be set by caller
        }
        
        if content_type in [ContentType.TEXT, ContentType.HTML]:
            text = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
            
            # Safe text features
            features.update({
                'char_count': len(text),
                'word_count': len(text.split()),
                'line_count': text.count('\n') + 1,
                'has_html': '<' in text and '>' in text,
                'language': self._detect_language_safe(text[:1000]),
                'url_count': len(re.findall(r'https?://[^\s<>"\']+', text)),
                'email_count': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)),
            })
            
            # Safe keyword extraction (common, non-sensitive)
            safe_keywords = [
                'forum', 'market', 'shop', 'blog', 'wiki', 'library',
                'login', 'register', 'search', 'contact', 'about',
                'privacy', 'terms', 'policy', 'faq', 'help',
            ]
            
            found_keywords = []
            text_lower = text.lower()
            for keyword in safe_keywords:
                if keyword in text_lower:
                    found_keywords.append(keyword)
            
            features['safe_keywords'] = found_keywords
        
        elif content_type == ContentType.IMAGE:
            try:
                image = Image.open(io.BytesIO(content))
                features.update({
                    'width': image.size[0],
                    'height': image.size[1],
                    'format': image.format,
                    'mode': image.mode,
                })
            except Exception:
                pass
        
        return features
    
    def _detect_language_safe(self, text: str) -> str:
        """Safely detect language without external dependencies.
        
        Args:
            text: Text to analyze
            
        Returns:
            Language code or 'unknown'
        """
        # Simple character-based detection
        # This is very basic - in production use a proper language detector
        common_ranges = {
            'en': (0x0041, 0x007A),  # Basic Latin
            'ru': (0x0410, 0x044F),  # Cyrillic
            'ar': (0x0600, 0x06FF),  # Arabic
            'zh': (0x4E00, 0x9FFF),  # CJK Unified Ideographs
        }
        
        char_counts = {}
        for char in text[:500]:  # Check first 500 chars
            code = ord(char)
            for lang, (start, end) in common_ranges.items():
                if start <= code <= end:
                    char_counts[lang] = char_counts.get(lang, 0) + 1
        
        if char_counts:
            return max(char_counts.items(), key=lambda x: x[1])[0]
        
        return 'unknown'