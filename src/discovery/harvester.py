"""
URL harvester - extracts onion links from HTML, text, and binary content.
"""

import re
import hashlib
import base64
from typing import List, Set, Tuple, Optional, Dict, Any
from urllib.parse import urljoin, urlparse
import logging
import binascii

from src.utils.logger import get_logger

logger = get_logger(__name__)


class OnionHarvester:
    """Extracts onion addresses from various content types."""
    
    # Regex patterns for onion address discovery
    # v2 onion addresses (16 chars)
    V2_ONION_PATTERN = re.compile(
        r'(?:http://|https://)?'
        r'([a-z2-7]{16})\.onion'
        r'(?:[/?#][^\s<>"]*)?',
        re.IGNORECASE
    )
    
    # v3 onion addresses (56 chars)
    V3_ONION_PATTERN = re.compile(
        r'(?:http://|https://)?'
        r'([a-z2-7]{56})\.onion'
        r'(?:[/?#][^\s<>"]*)?',
        re.IGNORECASE
    )
    
    # Base32 encoded strings that might be onion addresses
    BASE32_PATTERN = re.compile(
        r'[A-Z2-7]{16,56}',
        re.IGNORECASE
    )
    
    # Common patterns where onion addresses might be hidden
    HIDDEN_PATTERNS = [
        # In HTML attributes
        r'href=["\']([^"\']+\.onion[^"\']*)["\']',
        r'src=["\']([^"\']+\.onion[^"\']*)["\']',
        r'action=["\']([^"\']+\.onion[^"\']*)["\']',
        
        # In text with common prefixes
        r'(?:onion:\s*|tor:\s*|hidden:\s*)([a-z2-7]{16,56}\.onion)',
        
        # In code/comments
        r'//\s*([a-z2-7]{16,56}\.onion)',
        r'#\s*([a-z2-7]{16,56}\.onion)',
        r'--\s*([a-z2-7]{16,56}\.onion)',
        
        # In JSON/XML
        r'["\']([a-z2-7]{16,56}\.onion)["\']',
    ]
    
    def __init__(self, validate_onion: bool = True):
        """Initialize the harvester.
        
        Args:
            validate_onion: Whether to validate onion address format
        """
        self.validate_onion = validate_onion
        self.compiled_hidden_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.HIDDEN_PATTERNS
        ]
        
    def extract_from_html(self, html_content: str, base_url: Optional[str] = None) -> Set[str]:
        """Extract onion addresses from HTML content.
        
        Args:
            html_content: HTML string to parse
            base_url: Base URL for resolving relative links
            
        Returns:
            Set of discovered onion URLs
        """
        discovered = set()
        
        # Extract using regex patterns
        discovered.update(self._extract_with_patterns(html_content))
        
        # Parse HTML for links (simple approach, can be enhanced with BeautifulSoup)
        # Look for anchor tags
        anchor_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(anchor_pattern, html_content, re.IGNORECASE):
            href = match.group(1)
            onion_url = self._normalize_url(href, base_url)
            if onion_url and self._is_onion_url(onion_url):
                discovered.add(onion_url)
        
        # Look for link tags
        link_pattern = r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(link_pattern, html_content, re.IGNORECASE):
            href = match.group(1)
            onion_url = self._normalize_url(href, base_url)
            if onion_url and self._is_onion_url(onion_url):
                discovered.add(onion_url)
        
        # Look for script tags
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(script_pattern, html_content, re.IGNORECASE):
            src = match.group(1)
            onion_url = self._normalize_url(src, base_url)
            if onion_url and self._is_onion_url(onion_url):
                discovered.add(onion_url)
        
        # Look for form actions
        form_pattern = r'<form[^>]+action=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(form_pattern, html_content, re.IGNORECASE):
            action = match.group(1)
            onion_url = self._normalize_url(action, base_url)
            if onion_url and self._is_onion_url(onion_url):
                discovered.add(onion_url)
        
        return discovered
    
    def extract_from_text(self, text_content: str) -> Set[str]:
        """Extract onion addresses from plain text.
        
        Args:
            text_content: Text string to parse
            
        Returns:
            Set of discovered onion URLs
        """
        discovered = set()
        
        # Extract using regex patterns
        discovered.update(self._extract_with_patterns(text_content))
        
        # Look for base32 encoded strings that might be onion addresses
        for match in self.BASE32_PATTERN.finditer(text_content):
            candidate = match.group(0)
            # Check if it could be an onion address
            if self._could_be_onion(candidate):
                # Try to reconstruct URL
                for prefix in ['http://', 'https://']:
                    potential_url = f"{prefix}{candidate.lower()}.onion"
                    if self._is_onion_url(potential_url):
                        discovered.add(potential_url)
        
        return discovered
    
    def extract_from_binary(self, binary_content: bytes, mime_type: Optional[str] = None) -> Set[str]:
        """Extract onion addresses from binary content.
        
        Args:
            binary_content: Binary data to parse
            mime_type: MIME type hint for parsing
            
        Returns:
            Set of discovered onion URLs
        """
        discovered = set()
        
        # Try to decode as text (common in PDFs, docs, etc.)
        try:
            # Try UTF-8
            text_content = binary_content.decode('utf-8', errors='ignore')
            discovered.update(self.extract_from_text(text_content))
        except UnicodeDecodeError:
            # Try other encodings
            for encoding in ['latin-1', 'iso-8859-1', 'cp1252']:
                try:
                    text_content = binary_content.decode(encoding, errors='ignore')
                    discovered.update(self.extract_from_text(text_content))
                    break
                except UnicodeDecodeError:
                    continue
        
        # Look for base32 patterns in raw bytes
        # Convert to hex and look for patterns
        hex_content = binascii.hexlify(binary_content).decode('ascii')
        
        # Look for patterns that might be base32 in hex
        # This is heuristic and may have false positives
        hex_pattern = re.compile(r'[0-9a-f]{32,112}', re.IGNORECASE)
        for match in hex_pattern.finditer(hex_content):
            hex_str = match.group(0)
            # Try to convert hex to bytes to base32
            try:
                bytes_data = binascii.unhexlify(hex_str)
                # Skip if not valid for base32
                if len(bytes_data) % 5 == 0:  # Base32 requires multiples of 5 bytes
                    base32_str = base64.b32encode(bytes_data).decode('ascii').rstrip('=')
                    if self._could_be_onion(base32_str):
                        for prefix in ['http://', 'https://']:
                            potential_url = f"{prefix}{base32_str.lower()}.onion"
                            if self._is_onion_url(potential_url):
                                discovered.add(potential_url)
            except (binascii.Error, UnicodeDecodeError):
                continue
        
        return discovered
    
    def _extract_with_patterns(self, content: str) -> Set[str]:
        """Extract onion addresses using regex patterns.
        
        Args:
            content: Content to search
            
        Returns:
            Set of discovered onion URLs
        """
        discovered = set()
        
        # Extract v2 onion addresses
        for match in self.V2_ONION_PATTERN.finditer(content):
            url = match.group(0)
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            if self._is_onion_url(url):
                discovered.add(url)
        
        # Extract v3 onion addresses
        for match in self.V3_ONION_PATTERN.finditer(content):
            url = match.group(0)
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            if self._is_onion_url(url):
                discovered.add(url)
        
        # Extract from hidden patterns
        for pattern in self.compiled_hidden_patterns:
            for match in pattern.finditer(content):
                url = match.group(1)
                if not url.startswith(('http://', 'https://')):
                    url = f'http://{url}'
                if self._is_onion_url(url):
                    discovered.add(url)
        
        return discovered
    
    def _normalize_url(self, url: str, base_url: Optional[str] = None) -> Optional[str]:
        """Normalize URL and resolve relative URLs.
        
        Args:
            url: URL to normalize
            base_url: Base URL for resolving relative URLs
            
        Returns:
            Normalized URL or None if invalid
        """
        if not url or url.strip() == '':
            return None
        
        # Remove whitespace
        url = url.strip()
        
        # Handle common prefixes
        if url.startswith('//'):
            url = f'http:{url}'
        elif url.startswith('/'):
            if base_url:
                url = urljoin(base_url, url)
            else:
                return None
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            # Check if it starts with onion address
            if '.onion' in url and not url.split('.')[0].startswith('http'):
                url = f'http://{url}'
            else:
                return None
        
        # Parse URL to ensure it's valid
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            return parsed.geturl()
        except Exception:
            return None
    
    def _is_onion_url(self, url: str) -> bool:
        """Check if URL is a valid onion address.
        
        Args:
            url: URL to check
            
        Returns:
            True if valid onion URL
        """
        if not self.validate_onion:
            return '.onion' in url.lower()
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            
            if not hostname.endswith('.onion'):
                return False
            
            onion_part = hostname[:-6]  # Remove '.onion'
            
            # Check length for v2 (16 chars) or v3 (56 chars)
            if len(onion_part) not in [16, 56]:
                return False
            
            # Check characters (base32: a-z2-7)
            if not re.match(r'^[a-z2-7]+$', onion_part):
                return False
            
            # Additional validation for v3
            if len(onion_part) == 56:
                # v3 addresses have specific structure
                # First character indicates version (should be 3 for v3)
                if onion_part[0] != '3':
                    return False
                # Last character is checksum
                # We could implement full checksum validation here
            
            return True
            
        except Exception:
            return False
    
    def _could_be_onion(self, candidate: str) -> bool:
        """Check if string could be an onion address.
        
        Args:
            candidate: String to check
            
        Returns:
            True if could be onion address
        """
        candidate = candidate.lower()
        
        # Check length
        if len(candidate) not in [16, 56]:
            return False
        
        # Check characters (base32)
        if not re.match(r'^[a-z2-7]+$', candidate):
            return False
        
        # Additional check for v3
        if len(candidate) == 56 and candidate[0] != '3':
            return False
        
        return True
    
    def extract_from_content(
        self, 
        content: Any, 
        content_type: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> Set[str]:
        """Extract onion addresses from any content type.
        
        Args:
            content: Content to parse (str, bytes, etc.)
            content_type: MIME type hint
            base_url: Base URL for resolving relative links
            
        Returns:
            Set of discovered onion URLs
        """
        discovered = set()
        
        if isinstance(content, str):
            # Try as HTML first if content_type suggests it
            if content_type and 'html' in content_type.lower():
                discovered.update(self.extract_from_html(content, base_url))
            else:
                discovered.update(self.extract_from_text(content))
        elif isinstance(content, bytes):
            discovered.update(self.extract_from_binary(content, content_type))
        else:
            logger.warning(f"Unsupported content type: {type(content)}")
        
        return discovered
    
    def filter_known_sites(
        self, 
        discovered_urls: Set[str], 
        known_urls: Set[str]
    ) -> Tuple[Set[str], Set[str]]:
        """Filter out already known URLs.
        
        Args:
            discovered_urls: Newly discovered URLs
            known_urls: Already known URLs
            
        Returns:
            Tuple of (new_urls, duplicate_urls)
        """
        new_urls = discovered_urls - known_urls
        duplicate_urls = discovered_urls & known_urls
        return new_urls, duplicate_urls
    
    def calculate_content_hash(self, content: Any) -> str:
        """Calculate hash of content for deduplication.
        
        Args:
            content: Content to hash
            
        Returns:
            SHA256 hash of content
        """
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        elif isinstance(content, bytes):
            content_bytes = content
        else:
            content_bytes = str(content).encode('utf-8')
        
        return hashlib.sha256(content_bytes).hexdigest()