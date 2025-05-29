#!/usr/bin/env python3
"""
Threat Intelligence Module for SharpEye
Provides integration with threat intelligence platforms like MISP, AlienVault OTX, and Mandiant.
Allows querying for indicators of compromise (IOCs) and caching results.
"""

import os
import re
import json
import time
import logging
import threading
import ipaddress
import hashlib
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
from enum import Enum, auto
from collections import OrderedDict
from typing import Dict, List, Set, Union, Optional, Any, Tuple

# Suppress insecure request warnings for internal/test environments
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class IOCType(Enum):
    """Indicator of Compromise Types"""
    IP = auto()
    DOMAIN = auto()
    URL = auto()
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    EMAIL = auto()
    FILENAME = auto()
    UNKNOWN = auto()

class ThreatIntelligenceCache:
    """
    Thread-safe LRU cache for threat intelligence data with TTL
    """
    
    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        """
        Initialize cache with size limit and TTL

        Args:
            max_size: Maximum number of items to store in cache
            ttl_seconds: Time-to-live for cache entries in seconds
        """
        self._cache = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self._logger = logging.getLogger('sharpeye.threat_intelligence.cache')
        
        # Start cache cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_expired_entries,
            daemon=True,
            name="ThreatIntelCacheCleanup"
        )
        self._cleanup_thread.start()
    
    def get(self, key: str) -> Optional[Dict]:
        """
        Get item from cache if it exists and is not expired

        Args:
            key: Cache key to look up

        Returns:
            Cached value or None if not in cache or expired
        """
        with self._lock:
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            if time.time() > entry['expires']:
                # Entry expired, remove it
                self._cache.pop(key)
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return entry['data']
    
    def set(self, key: str, value: Dict, ttl_seconds: Optional[int] = None) -> None:
        """
        Add item to cache with expiration time

        Args:
            key: Cache key
            value: Value to store
            ttl_seconds: Optional override for TTL, otherwise uses default
        """
        with self._lock:
            # Set expiration time
            expiration = time.time() + (ttl_seconds if ttl_seconds is not None else self._ttl_seconds)
            
            # Add/update entry
            self._cache[key] = {
                'data': value,
                'expires': expiration
            }
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            
            # Check if we need to remove oldest items
            if len(self._cache) > self._max_size:
                # Remove oldest item (first item in OrderedDict)
                self._cache.popitem(last=False)
    
    def clear(self) -> None:
        """Clear all items from cache"""
        with self._lock:
            self._cache.clear()
    
    def _cleanup_expired_entries(self) -> None:
        """
        Background thread to periodically clean up expired entries
        """
        while True:
            try:
                # Sleep for 1/3 of TTL before cleanup
                time.sleep(self._ttl_seconds / 3)
                
                # Clean up expired entries
                with self._lock:
                    current_time = time.time()
                    expired_keys = [k for k, v in self._cache.items() if current_time > v['expires']]
                    
                    if expired_keys:
                        self._logger.debug(f"Cleaning up {len(expired_keys)} expired cache entries")
                        for key in expired_keys:
                            self._cache.pop(key, None)
            except Exception as e:
                self._logger.error(f"Error in cache cleanup thread: {e}")
                # Continue running even if there's an error

class IOC:
    """
    Class representing an Indicator of Compromise (IOC) with standardized fields
    """
    
    def __init__(self, 
                 value: str, 
                 ioc_type: IOCType,
                 source: str, 
                 malicious: bool = False, 
                 confidence: float = 0.0,
                 tags: List[str] = None,
                 first_seen: Optional[datetime] = None,
                 last_seen: Optional[datetime] = None,
                 description: str = "",
                 source_info: Dict = None):
        """
        Initialize an IOC with standard fields

        Args:
            value: The IOC value (IP, domain, hash, etc.)
            ioc_type: Type of the IOC
            source: Source of the intelligence (platform name)
            malicious: Whether the IOC is considered malicious
            confidence: Confidence score (0.0-1.0)
            tags: List of tags associated with the IOC
            first_seen: When the IOC was first observed
            last_seen: When the IOC was last observed
            description: Human-readable description
            source_info: Additional source-specific information
        """
        self.value = value
        self.ioc_type = ioc_type
        self.source = source
        self.malicious = malicious
        self.confidence = confidence
        self.tags = tags or []
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.description = description
        self.source_info = source_info or {}
    
    def to_dict(self) -> Dict:
        """Convert IOC to dictionary representation"""
        return {
            'value': self.value,
            'type': self.ioc_type.name,
            'source': self.source,
            'malicious': self.malicious,
            'confidence': self.confidence,
            'tags': self.tags,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'description': self.description,
            'source_info': self.source_info
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'IOC':
        """Create IOC instance from dictionary"""
        # Convert string IOC type to enum
        if isinstance(data.get('type'), str):
            try:
                ioc_type = IOCType[data['type']]
            except KeyError:
                ioc_type = IOCType.UNKNOWN
        else:
            ioc_type = data.get('type', IOCType.UNKNOWN)
        
        # Parse date strings to datetime objects
        first_seen = None
        if data.get('first_seen'):
            try:
                first_seen = datetime.fromisoformat(data['first_seen'])
            except (ValueError, TypeError):
                pass
        
        last_seen = None
        if data.get('last_seen'):
            try:
                last_seen = datetime.fromisoformat(data['last_seen'])
            except (ValueError, TypeError):
                pass
        
        return cls(
            value=data.get('value', ''),
            ioc_type=ioc_type,
            source=data.get('source', ''),
            malicious=data.get('malicious', False),
            confidence=data.get('confidence', 0.0),
            tags=data.get('tags', []),
            first_seen=first_seen,
            last_seen=last_seen,
            description=data.get('description', ''),
            source_info=data.get('source_info', {})
        )
    
    def __str__(self) -> str:
        """String representation of IOC"""
        return f"IOC({self.value}, {self.ioc_type.name}, malicious={self.malicious}, confidence={self.confidence:.2f})"

class ThreatIntelligenceProvider:
    """
    Base class for all threat intelligence providers
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize provider with configuration

        Args:
            config: Provider-specific configuration
        """
        self.config = config or {}
        self.name = "base"
        self.logger = logging.getLogger(f'sharpeye.threat_intelligence.{self.name}')
        
        # Default request timeout
        self.timeout = self.config.get('timeout', 10)
        
        # Cache for API responses
        self.cache = ThreatIntelligenceCache(
            max_size=self.config.get('cache_size', 10000),
            ttl_seconds=self.config.get('cache_ttl', 3600)
        )
        
        # Rate limiting
        self._last_request_time = 0
        self._min_request_interval = self.config.get('min_request_interval', 0.2)  # 5 requests per second max
        self._request_lock = threading.Lock()
    
    def check_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """
        Check if an indicator is in the threat intelligence database

        Args:
            value: IOC value to check
            ioc_type: Optional type of IOC, will be auto-detected if not provided

        Returns:
            IOC object if found, None otherwise
        """
        raise NotImplementedError("Subclasses must implement check_ioc method")
    
    def test_connection(self) -> bool:
        """
        Test connection to the threat intelligence platform

        Returns:
            True if connection is successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement test_connection method")
    
    def _throttled_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make a throttled HTTP request to respect rate limits

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        with self._request_lock:
            # Calculate time since last request
            now = time.time()
            time_since_last_request = now - self._last_request_time
            
            # If we need to wait to respect rate limit, sleep
            if time_since_last_request < self._min_request_interval:
                sleep_time = self._min_request_interval - time_since_last_request
                time.sleep(sleep_time)
            
            # Make the request
            response = requests.request(method, url, timeout=self.timeout, **kwargs)
            
            # Update last request time
            self._last_request_time = time.time()
            
            return response
    
    def _handle_request_error(self, response: requests.Response, url: str) -> None:
        """
        Handle HTTP request errors with appropriate logging

        Args:
            response: Response object to check
            url: URL being requested (for logging)
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            status_code = response.status_code
            
            if status_code == 401:
                self.logger.error(f"Authentication error accessing {url} - check API key")
            elif status_code == 403:
                self.logger.error(f"Access forbidden to {url} - check permissions")
            elif status_code == 404:
                self.logger.debug(f"Resource not found at {url}")
            elif status_code == 429:
                self.logger.warning(f"Rate limit exceeded for {url}")
            else:
                self.logger.error(f"HTTP error {status_code} accessing {url}: {str(e)}")
            
            raise e


class MISPProvider(ThreatIntelligenceProvider):
    """
    MISP (Malware Information Sharing Platform) provider
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize MISP provider with configuration

        Args:
            config: Provider-specific configuration including URL and API key
        """
        config = config or {}
        super().__init__(config)
        self.name = "misp"
        
        # MISP configuration
        self.misp_url = self.config.get('url')
        self.api_key = self.config.get('api_key')
        self.verify_ssl = self.config.get('verify_ssl', True)
        
        # Ensure URL ends with /
        if self.misp_url and not self.misp_url.endswith('/'):
            self.misp_url += '/'
        
        # Configure requests session
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self.session.verify = self.verify_ssl
    
    def check_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """
        Check if an indicator is in MISP

        Args:
            value: IOC value to check
            ioc_type: Optional type of IOC, will be auto-detected if not provided

        Returns:
            IOC object if found, None otherwise
        """
        if not self.misp_url or not self.api_key:
            self.logger.warning("MISP URL or API key not configured")
            return None
        
        # Determine IOC type if not provided
        if ioc_type is None:
            ioc_type = detect_ioc_type(value)
            if ioc_type == IOCType.UNKNOWN:
                self.logger.warning(f"Could not determine IOC type for {value}")
                return None
        
        # Check cache first
        cache_key = f"misp:{ioc_type.name}:{value}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return IOC.from_dict(cached_result)
        
        try:
            # Map IOC type to MISP type
            misp_type = self._get_misp_type(ioc_type)
            if not misp_type:
                self.logger.warning(f"Unsupported IOC type for MISP: {ioc_type.name}")
                return None
            
            # Query MISP for the attribute
            response = self._throttled_request(
                'POST',
                f"{self.misp_url}attributes/restSearch",
                json={"value": value, "type": misp_type},
                headers=self.session.headers,
                verify=self.verify_ssl
            )
            
            self._handle_request_error(response, f"{self.misp_url}attributes/restSearch")
            
            # Process response
            result = response.json()
            attributes = result.get('response', {}).get('Attribute', [])
            
            if not attributes:
                return None
            
            # Process the first matching attribute
            attribute = attributes[0]
            
            # Extract event details if available
            event_id = attribute.get('event_id')
            event_info = ""
            event_tags = []
            
            if event_id:
                event_response = self._throttled_request(
                    'GET',
                    f"{self.misp_url}events/view/{event_id}",
                    headers=self.session.headers,
                    verify=self.verify_ssl
                )
                
                if event_response.status_code == 200:
                    event_data = event_response.json()
                    event = event_data.get('Event', {})
                    event_info = event.get('info', '')
                    event_tags = [tag.get('name', '') for tag in event.get('Tag', [])]
            
            # Calculate confidence based on tags and other factors
            confidence = self._calculate_confidence(attribute, event_tags)
            
            # Determine maliciousness
            malicious = self._is_malicious(attribute, event_tags)
            
            # Extract tags
            attribute_tags = [tag.get('name', '') for tag in attribute.get('Tag', [])]
            tags = list(set(attribute_tags + event_tags))
            
            # Parse timestamps
            first_seen = None
            if attribute.get('first_seen'):
                try:
                    first_seen = datetime.fromisoformat(attribute['first_seen'].replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass
            
            last_seen = None
            if attribute.get('last_seen'):
                try:
                    last_seen = datetime.fromisoformat(attribute['last_seen'].replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass
            
            # Create IOC object
            ioc = IOC(
                value=value,
                ioc_type=ioc_type,
                source="MISP",
                malicious=malicious,
                confidence=confidence,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                description=event_info,
                source_info={
                    'event_id': event_id,
                    'attribute_id': attribute.get('id'),
                    'attribute_type': attribute.get('type'),
                    'attribute_category': attribute.get('category')
                }
            )
            
            # Cache the result
            self.cache.set(cache_key, ioc.to_dict())
            
            return ioc
            
        except Exception as e:
            self.logger.error(f"Error checking IOC {value} in MISP: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test connection to MISP platform

        Returns:
            True if connection is successful, False otherwise
        """
        if not self.misp_url or not self.api_key:
            self.logger.warning("MISP URL or API key not configured")
            return False
        
        try:
            response = self._throttled_request(
                'GET',
                f"{self.misp_url}servers/getVersion",
                headers=self.session.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                version_info = response.json()
                self.logger.info(f"Successfully connected to MISP version {version_info.get('version', 'unknown')}")
                return True
            else:
                self.logger.warning(f"Failed to connect to MISP: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing connection to MISP: {e}")
            return False
    
    def _get_misp_type(self, ioc_type: IOCType) -> str:
        """
        Map IOCType to MISP attribute type

        Args:
            ioc_type: IOC type to map

        Returns:
            MISP attribute type string
        """
        misp_types = {
            IOCType.IP: 'ip-dst',  # Also could be ip-src based on context
            IOCType.DOMAIN: 'domain',
            IOCType.URL: 'url',
            IOCType.MD5: 'md5',
            IOCType.SHA1: 'sha1',
            IOCType.SHA256: 'sha256',
            IOCType.EMAIL: 'email-src',
            IOCType.FILENAME: 'filename'
        }
        return misp_types.get(ioc_type, '')
    
    def _calculate_confidence(self, attribute: Dict, event_tags: List[str]) -> float:
        """
        Calculate confidence score based on attribute data

        Args:
            attribute: MISP attribute data
            event_tags: Tags from the parent event

        Returns:
            Confidence score between 0-1
        """
        confidence = 0.5  # Start with neutral confidence
        
        # Increase confidence based on attribute characteristics
        if attribute.get('to_ids', False):
            confidence += 0.2
        
        # Check if there are sightings
        if int(attribute.get('sightings_count', 0)) > 0:
            confidence += 0.1
        
        # Check tags for confidence indicators
        all_tags = event_tags + [tag.get('name', '') for tag in attribute.get('Tag', [])]
        for tag in all_tags:
            tag_lower = tag.lower()
            
            # Tags that increase confidence
            if any(indicator in tag_lower for indicator in ['malicious', 'threat', 'attack', 'compromise']):
                confidence += 0.1
            
            # Tags with explicit confidence levels
            if 'high-confidence' in tag_lower:
                confidence += 0.2
            elif 'medium-confidence' in tag_lower:
                confidence += 0.1
            elif 'low-confidence' in tag_lower:
                confidence -= 0.1
            
            # False positive tags reduce confidence
            if any(indicator in tag_lower for indicator in ['false-positive', 'benign']):
                confidence -= 0.3
        
        # Ensure confidence is between 0-1
        return max(0.0, min(1.0, confidence))
    
    def _is_malicious(self, attribute: Dict, event_tags: List[str]) -> bool:
        """
        Determine if an attribute represents a malicious IOC

        Args:
            attribute: MISP attribute data
            event_tags: Tags from the parent event

        Returns:
            True if considered malicious, False otherwise
        """
        # Check IDS flag (Intrusion Detection System flag)
        if attribute.get('to_ids', False):
            return True
        
        # Check tags for maliciousness indicators
        all_tags = event_tags + [tag.get('name', '') for tag in attribute.get('Tag', [])]
        for tag in all_tags:
            tag_lower = tag.lower()
            
            # Tags indicating maliciousness
            if any(indicator in tag_lower for indicator in [
                'malicious', 'malware', 'attack', 'threat', 'trojan', 'ransomware',
                'botnet', 'spyware', 'c2', 'command-and-control'
            ]):
                return True
            
            # Tags indicating benign/false positive
            if any(indicator in tag_lower for indicator in ['false-positive', 'benign']):
                return False
        
        # Default based on confidence
        confidence = self._calculate_confidence(attribute, event_tags)
        return confidence >= 0.7  # Consider malicious if high confidence


class OTXProvider(ThreatIntelligenceProvider):
    """
    AlienVault OTX (Open Threat Exchange) provider
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize OTX provider with configuration

        Args:
            config: Provider-specific configuration including API key
        """
        config = config or {}
        super().__init__(config)
        self.name = "otx"
        
        # OTX configuration
        self.api_key = self.config.get('api_key')
        self.base_url = self.config.get('base_url', 'https://otx.alienvault.com/api/v1')
        
        # Ensure base URL doesn't end with /
        if self.base_url.endswith('/'):
            self.base_url = self.base_url[:-1]
        
        # Configure requests session
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                'X-OTX-API-KEY': self.api_key,
                'Accept': 'application/json'
            })
    
    def check_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """
        Check if an indicator is in OTX

        Args:
            value: IOC value to check
            ioc_type: Optional type of IOC, will be auto-detected if not provided

        Returns:
            IOC object if found, None otherwise
        """
        if not self.api_key:
            self.logger.warning("OTX API key not configured")
            return None
        
        # Determine IOC type if not provided
        if ioc_type is None:
            ioc_type = detect_ioc_type(value)
            if ioc_type == IOCType.UNKNOWN:
                self.logger.warning(f"Could not determine IOC type for {value}")
                return None
        
        # Check cache first
        cache_key = f"otx:{ioc_type.name}:{value}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return IOC.from_dict(cached_result)
        
        try:
            # Map to OTX section
            otx_section = self._get_otx_section(ioc_type)
            if not otx_section:
                self.logger.warning(f"Unsupported IOC type for OTX: {ioc_type.name}")
                return None
            
            # Handle hash special case (OTX uses /file/file/ for file hashes)
            if ioc_type in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]:
                url = f"{self.base_url}/indicators/file/{value}/general"
            else:
                url = f"{self.base_url}/indicators/{otx_section}/{value}/general"
            
            # Query OTX API
            response = self._throttled_request(
                'GET',
                url,
                headers=self.session.headers
            )
            
            # If not found (404), return None
            if response.status_code == 404:
                return None
            
            self._handle_request_error(response, url)
            
            # Process response
            result = response.json()
            
            # Get pulse (threat) information
            pulses_url = f"{self.base_url}/indicators/{otx_section}/{value}/pulses"
            pulses_response = self._throttled_request(
                'GET',
                pulses_url,
                headers=self.session.headers
            )
            
            pulses = []
            if pulses_response.status_code == 200:
                pulses_data = pulses_response.json()
                pulses = pulses_data.get('results', [])
            
            # Extract tags and descriptions from pulses
            tags = []
            descriptions = []
            for pulse in pulses:
                pulse_tags = pulse.get('tags', [])
                tags.extend(pulse_tags)
                
                if pulse.get('name'):
                    descriptions.append(pulse.get('name'))
            
            # Remove duplicates
            tags = list(set(tags))
            
            # Join descriptions with separator
            description = " | ".join(descriptions[:5])  # Limit to first 5 for brevity
            
            # Calculate confidence and maliciousness
            confidence = self._calculate_confidence(result, pulses)
            malicious = bool(pulses) and confidence >= 0.5
            
            # Parse timestamps - OTX uses created/modified fields
            first_seen = None
            if result.get('created'):
                try:
                    first_seen = datetime.strptime(result['created'], "%Y-%m-%dT%H:%M:%S.%f")
                except (ValueError, TypeError):
                    pass
            
            last_seen = None
            if result.get('modified'):
                try:
                    last_seen = datetime.strptime(result['modified'], "%Y-%m-%dT%H:%M:%S.%f")
                except (ValueError, TypeError):
                    pass
            
            # Create IOC object
            ioc = IOC(
                value=value,
                ioc_type=ioc_type,
                source="AlienVault OTX",
                malicious=malicious,
                confidence=confidence,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                description=description,
                source_info={
                    'pulse_count': len(pulses),
                    'analysis': result.get('analysis', {}),
                    'type': result.get('type', '')
                }
            )
            
            # Cache the result
            self.cache.set(cache_key, ioc.to_dict())
            
            return ioc
            
        except Exception as e:
            self.logger.error(f"Error checking IOC {value} in OTX: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test connection to OTX platform

        Returns:
            True if connection is successful, False otherwise
        """
        if not self.api_key:
            self.logger.warning("OTX API key not configured")
            return False
        
        try:
            # Test API by getting user information
            response = self._throttled_request(
                'GET',
                f"{self.base_url}/user/me",
                headers=self.session.headers
            )
            
            if response.status_code == 200:
                user_data = response.json()
                username = user_data.get('username', 'unknown')
                self.logger.info(f"Successfully connected to OTX as user: {username}")
                return True
            else:
                self.logger.warning(f"Failed to connect to OTX: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing connection to OTX: {e}")
            return False
    
    def _get_otx_section(self, ioc_type: IOCType) -> str:
        """
        Map IOCType to OTX API section

        Args:
            ioc_type: IOC type to map

        Returns:
            OTX API section string
        """
        otx_sections = {
            IOCType.IP: 'IPv4',
            IOCType.DOMAIN: 'domain',
            IOCType.URL: 'url',
            IOCType.MD5: 'file',
            IOCType.SHA1: 'file',
            IOCType.SHA256: 'file',
            IOCType.EMAIL: 'email',
            IOCType.FILENAME: 'file'  # Note: filename alone isn't ideal for OTX
        }
        return otx_sections.get(ioc_type, '')
    
    def _calculate_confidence(self, general_data: Dict, pulses: List[Dict]) -> float:
        """
        Calculate confidence score based on OTX data

        Args:
            general_data: General indicator data from OTX
            pulses: List of OTX pulses containing the indicator

        Returns:
            Confidence score between 0-1
        """
        # Base confidence on number of pulses
        pulse_count = len(pulses)
        if pulse_count == 0:
            return 0.0
        
        # Base confidence starts low and increases with pulse count
        base_confidence = min(0.8, 0.3 + (pulse_count * 0.05))
        
        # Adjust confidence based on pulse attributes
        confidence_adjustment = 0.0
        
        # Check the malicious status of pulses
        malicious_pulse_count = 0
        adversary_count = 0
        
        for pulse in pulses:
            # Created by OTX team or trusted source?
            if pulse.get('author_name', '').lower() in ['alienvault', 'otx']:
                confidence_adjustment += 0.1
            
            # Has adversary/threat actor information?
            if pulse.get('adversary'):
                adversary_count += 1
            
            # Check tags for threat indicators
            for tag in pulse.get('tags', []):
                tag_lower = tag.lower()
                if any(term in tag_lower for term in [
                    'malware', 'ransomware', 'trojan', 'botnet', 'spyware',
                    'exploit', 'apt', 'c2', 'command-and-control'
                ]):
                    malicious_pulse_count += 1
                    break
        
        # Add confidence for adversary attribution
        if adversary_count > 0:
            confidence_adjustment += min(0.1, adversary_count * 0.02)
        
        # Add confidence for malicious pulse ratio
        if pulse_count > 0:
            malicious_ratio = malicious_pulse_count / pulse_count
            confidence_adjustment += malicious_ratio * 0.1
        
        # Final confidence calculation
        final_confidence = base_confidence + confidence_adjustment
        
        # Ensure confidence is between 0-1
        return max(0.0, min(1.0, final_confidence))


class MandiantProvider(ThreatIntelligenceProvider):
    """
    Mandiant Threat Intelligence provider
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize Mandiant provider with configuration

        Args:
            config: Provider-specific configuration including API key and API secret
        """
        config = config or {}
        super().__init__(config)
        self.name = "mandiant"
        
        # Mandiant configuration
        self.api_key = self.config.get('api_key')
        self.api_secret = self.config.get('api_secret')
        self.base_url = self.config.get('base_url', 'https://api.intelligence.mandiant.com')
        
        # Ensure base URL doesn't end with /
        if self.base_url.endswith('/'):
            self.base_url = self.base_url[:-1]
        
        # Authentication token and expiration
        self._auth_token = None
        self._token_expiry = datetime.now()
        self._auth_lock = threading.Lock()
    
    def check_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """
        Check if an indicator is in Mandiant Threat Intelligence

        Args:
            value: IOC value to check
            ioc_type: Optional type of IOC, will be auto-detected if not provided

        Returns:
            IOC object if found, None otherwise
        """
        if not self.api_key or not self.api_secret:
            self.logger.warning("Mandiant API credentials not configured")
            return None
        
        # Determine IOC type if not provided
        if ioc_type is None:
            ioc_type = detect_ioc_type(value)
            if ioc_type == IOCType.UNKNOWN:
                self.logger.warning(f"Could not determine IOC type for {value}")
                return None
        
        # Check cache first
        cache_key = f"mandiant:{ioc_type.name}:{value}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return IOC.from_dict(cached_result)
        
        # Ensure we have a valid auth token
        if not self._ensure_auth_token():
            self.logger.error("Failed to authenticate with Mandiant API")
            return None
        
        try:
            # Map to Mandiant indicator type
            mandiant_type = self._get_mandiant_type(ioc_type)
            if not mandiant_type:
                self.logger.warning(f"Unsupported IOC type for Mandiant: {ioc_type.name}")
                return None
            
            # Prepare API endpoint and parameters
            url = f"{self.base_url}/v4/indicator"
            params = {
                'value': value,
                'type': mandiant_type
            }
            
            # Set headers with auth token
            headers = {
                'Accept': 'application/json',
                'X-App-Name': 'SharpEye IDS',
                'Authorization': f'Bearer {self._auth_token}'
            }
            
            # Query Mandiant API
            response = self._throttled_request(
                'GET',
                url,
                headers=headers,
                params=params
            )
            
            # If not found (404), return None
            if response.status_code == 404:
                return None
            
            self._handle_request_error(response, url)
            
            # Process response
            result = response.json()
            indicators = result.get('indicators', [])
            
            if not indicators:
                return None
            
            # Get first matching indicator
            indicator = indicators[0]
            
            # Get associated reports and attributions if available
            reports = []
            actor_names = []
            
            if 'reports' in indicator:
                report_ids = [report.get('report_id') for report in indicator.get('reports', [])][:5]  # Limit to 5 reports
                
                for report_id in report_ids:
                    report_url = f"{self.base_url}/v4/report/{report_id}"
                    report_response = self._throttled_request(
                        'GET',
                        report_url,
                        headers=headers
                    )
                    
                    if report_response.status_code == 200:
                        report_data = report_response.json()
                        reports.append(report_data)
                        
                        # Extract actor information
                        for attribution in report_data.get('attributions', []):
                            if attribution.get('name'):
                                actor_names.append(attribution.get('name'))
            
            # Extract malware and threat information
            malware_names = []
            for item in indicator.get('malware', []):
                if item.get('name'):
                    malware_names.append(item.get('name'))
            
            # Generate description from reports and malware
            description_parts = []
            for report in reports[:2]:  # Limit to 2 reports for description
                if report.get('title'):
                    description_parts.append(report.get('title'))
            
            if malware_names:
                description_parts.append(f"Associated malware: {', '.join(malware_names)}")
            
            if actor_names:
                description_parts.append(f"Attributed to: {', '.join(set(actor_names))}")
            
            description = " | ".join(description_parts)
            
            # Extract confidence and calculate maliciousness
            mscore = indicator.get('mscore', 0)  # Mandiant score
            confidence = mscore / 100 if isinstance(mscore, (int, float)) else 0.5
            
            # Note: mscore of 50+ typically indicates malicious with medium-high confidence
            malicious = mscore >= 50
            
            # Extract tags
            tags = []
            for category in indicator.get('categories', []):
                tags.append(f"category:{category}")
                
            for malware in indicator.get('malware', []):
                if malware.get('name'):
                    tags.append(f"malware:{malware.get('name')}")
            
            for actor in actor_names:
                tags.append(f"actor:{actor}")
            
            # Parse timestamps
            first_seen = None
            if indicator.get('first_seen'):
                try:
                    first_seen = datetime.fromisoformat(indicator['first_seen'].replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass
            
            last_seen = None
            if indicator.get('last_seen'):
                try:
                    last_seen = datetime.fromisoformat(indicator['last_seen'].replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass
            
            # Create IOC object
            ioc = IOC(
                value=value,
                ioc_type=ioc_type,
                source="Mandiant",
                malicious=malicious,
                confidence=confidence,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                description=description,
                source_info={
                    'mscore': mscore,
                    'type': indicator.get('type'),
                    'sources': indicator.get('sources', []),
                    'malware': indicator.get('malware', []),
                    'reports': [r.get('title', '') for r in reports]
                }
            )
            
            # Cache the result
            self.cache.set(cache_key, ioc.to_dict())
            
            return ioc
            
        except Exception as e:
            self.logger.error(f"Error checking IOC {value} in Mandiant: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test connection to Mandiant platform

        Returns:
            True if connection is successful, False otherwise
        """
        if not self.api_key or not self.api_secret:
            self.logger.warning("Mandiant API credentials not configured")
            return False
        
        # Ensure we have a valid auth token
        if not self._ensure_auth_token():
            self.logger.error("Failed to authenticate with Mandiant API")
            return False
        
        try:
            # Test API by getting a simple resource
            headers = {
                'Accept': 'application/json',
                'X-App-Name': 'SharpEye IDS',
                'Authorization': f'Bearer {self._auth_token}'
            }
            
            response = self._throttled_request(
                'GET',
                f"{self.base_url}/v4/version",
                headers=headers
            )
            
            if response.status_code == 200:
                version_data = response.json()
                version = version_data.get('version', 'unknown')
                self.logger.info(f"Successfully connected to Mandiant API v{version}")
                return True
            else:
                self.logger.warning(f"Failed to connect to Mandiant API: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing connection to Mandiant API: {e}")
            return False
    
    def _get_mandiant_type(self, ioc_type: IOCType) -> str:
        """
        Map IOCType to Mandiant API indicator type

        Args:
            ioc_type: IOC type to map

        Returns:
            Mandiant API indicator type string
        """
        mandiant_types = {
            IOCType.IP: 'ip',
            IOCType.DOMAIN: 'domain',
            IOCType.URL: 'url',
            IOCType.MD5: 'md5',
            IOCType.SHA1: 'sha1',
            IOCType.SHA256: 'sha256',
            IOCType.EMAIL: 'email'
            # Note: FILENAME is not directly supported by Mandiant API
        }
        return mandiant_types.get(ioc_type, '')
    
    def _ensure_auth_token(self) -> bool:
        """
        Ensure we have a valid authentication token, refreshing if needed

        Returns:
            True if valid token is available, False otherwise
        """
        with self._auth_lock:
            # Check if token is still valid (with 5 minute buffer)
            if (self._auth_token and 
                self._token_expiry > datetime.now() + timedelta(minutes=5)):
                return True
            
            # Token needs refresh
            try:
                # Prepare authentication request
                auth_url = f"{self.base_url}/token"
                auth_headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json',
                    'X-App-Name': 'SharpEye IDS'
                }
                auth_data = {
                    'grant_type': 'client_credentials',
                    'client_id': self.api_key,
                    'client_secret': self.api_secret
                }
                
                # Make authentication request
                response = self._throttled_request(
                    'POST',
                    auth_url,
                    headers=auth_headers,
                    data=auth_data
                )
                
                if response.status_code != 200:
                    self.logger.error(f"Mandiant authentication failed: HTTP {response.status_code}")
                    return False
                
                # Process response
                auth_response = response.json()
                self._auth_token = auth_response.get('access_token')
                
                # Calculate token expiry
                expires_in = auth_response.get('expires_in', 3600)  # Default to 1 hour
                self._token_expiry = datetime.now() + timedelta(seconds=expires_in)
                
                self.logger.debug(f"Successfully authenticated with Mandiant API, token valid until {self._token_expiry}")
                return bool(self._auth_token)
                
            except Exception as e:
                self.logger.error(f"Error authenticating with Mandiant API: {e}")
                return False


class ThreatIntelligenceManager:
    """
    Manager class for threat intelligence providers
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize threat intelligence manager

        Args:
            config: Configuration dictionary for all providers
        """
        self.logger = logging.getLogger('sharpeye.threat_intelligence')
        self.config = config or {}
        
        # Load providers
        self.providers = {}
        self._load_providers()
        
        # Initialize cache for consolidated results
        self.cache = ThreatIntelligenceCache(
            max_size=self.config.get('cache_size', 10000),
            ttl_seconds=self.config.get('cache_ttl', 3600)
        )
    
    def _load_providers(self) -> None:
        """Load and initialize configured threat intelligence providers"""
        
        # Check which providers are enabled
        provider_configs = self.config.get('providers', {})
        
        # Initialize MISP provider if configured
        misp_config = provider_configs.get('misp', {})
        if misp_config.get('enabled', False):
            self.providers['misp'] = MISPProvider(misp_config)
            self.logger.info("MISP provider initialized")
        
        # Initialize OTX provider if configured
        otx_config = provider_configs.get('otx', {})
        if otx_config.get('enabled', False):
            self.providers['otx'] = OTXProvider(otx_config)
            self.logger.info("AlienVault OTX provider initialized")
        
        # Initialize Mandiant provider if configured
        mandiant_config = provider_configs.get('mandiant', {})
        if mandiant_config.get('enabled', False):
            self.providers['mandiant'] = MandiantProvider(mandiant_config)
            self.logger.info("Mandiant provider initialized")
        
        # Log provider count
        self.logger.info(f"Initialized {len(self.providers)} threat intelligence providers")
    
    def check_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> List[IOC]:
        """
        Check an indicator against all configured providers

        Args:
            value: IOC value to check
            ioc_type: Optional IOC type, will be auto-detected if not provided

        Returns:
            List of IOC objects from all providers that returned results
        """
        # Normalize value
        value = value.strip()
        
        # Auto-detect IOC type if not provided
        if ioc_type is None:
            ioc_type = detect_ioc_type(value)
            if ioc_type == IOCType.UNKNOWN:
                self.logger.warning(f"Could not determine IOC type for {value}")
                return []
        
        # Check cache for consolidated results
        cache_key = f"consolidated:{ioc_type.name}:{value}"
        cached_results = self.cache.get(cache_key)
        if cached_results:
            return [IOC.from_dict(ioc_dict) for ioc_dict in cached_results]
        
        # If no providers, return empty list
        if not self.providers:
            self.logger.warning("No threat intelligence providers configured")
            return []
        
        # Check each provider
        results = []
        for provider_name, provider in self.providers.items():
            try:
                ioc = provider.check_ioc(value, ioc_type)
                if ioc:
                    results.append(ioc)
            except Exception as e:
                self.logger.error(f"Error checking {value} with provider {provider_name}: {e}")
        
        # Cache consolidated results
        if results:
            self.cache.set(cache_key, [ioc.to_dict() for ioc in results])
        
        return results
    
    def is_malicious(self, value: str, ioc_type: Optional[IOCType] = None, 
                   min_confidence: float = 0.5, require_multiple_sources: bool = False) -> bool:
        """
        Check if an indicator is considered malicious by threat intelligence

        Args:
            value: IOC value to check
            ioc_type: Optional IOC type, will be auto-detected if not provided
            min_confidence: Minimum confidence threshold
            require_multiple_sources: Whether to require detection from multiple sources

        Returns:
            True if considered malicious, False otherwise
        """
        # Get results from all providers
        results = self.check_ioc(value, ioc_type)
        
        # No results found
        if not results:
            return False
        
        # Count malicious findings with sufficient confidence
        malicious_findings = [
            r for r in results 
            if r.malicious and r.confidence >= min_confidence
        ]
        
        # Check if we have sufficient malicious findings
        if require_multiple_sources:
            # Need malicious findings from at least 2 different sources
            sources = {r.source for r in malicious_findings}
            return len(sources) >= 2
        else:
            # At least one malicious finding with sufficient confidence
            return len(malicious_findings) > 0
    
    def test_connections(self) -> Dict[str, bool]:
        """
        Test connections to all configured providers

        Returns:
            Dictionary mapping provider names to connection status
        """
        results = {}
        
        for provider_name, provider in self.providers.items():
            try:
                status = provider.test_connection()
                results[provider_name] = status
                self.logger.info(f"Provider {provider_name} connection test: {'SUCCESS' if status else 'FAILED'}")
            except Exception as e:
                self.logger.error(f"Error testing connection to {provider_name}: {e}")
                results[provider_name] = False
        
        return results
    
    def get_ioc_context(self, value: str, ioc_type: Optional[IOCType] = None) -> Dict:
        """
        Get comprehensive context for an IOC from all sources

        Args:
            value: IOC value to check
            ioc_type: Optional IOC type, will be auto-detected if not provided

        Returns:
            Dictionary with consolidated context information
        """
        # Get results from all providers
        results = self.check_ioc(value, ioc_type)
        
        if not results:
            return {
                'value': value,
                'type': str(ioc_type.name) if ioc_type else 'UNKNOWN',
                'found': False,
                'malicious': False,
                'sources': []
            }
        
        # Determine if malicious based on aggregated data
        malicious_count = sum(1 for r in results if r.malicious)
        total_count = len(results)
        
        # Calculate average confidence
        avg_confidence = sum(r.confidence for r in results) / total_count if total_count > 0 else 0
        
        # Collect all unique tags
        all_tags = set()
        for r in results:
            all_tags.update(r.tags)
        
        # Collect source information
        sources = [
            {
                'name': r.source,
                'malicious': r.malicious,
                'confidence': r.confidence,
                'first_seen': r.first_seen.isoformat() if r.first_seen else None,
                'last_seen': r.last_seen.isoformat() if r.last_seen else None,
                'description': r.description
            }
            for r in results
        ]
        
        # Build consolidated context
        context = {
            'value': value,
            'type': str(results[0].ioc_type.name),
            'found': True,
            'malicious': malicious_count > 0,
            'malicious_sources': malicious_count,
            'total_sources': total_count,
            'average_confidence': avg_confidence,
            'tags': sorted(list(all_tags)),
            'sources': sources,
            'first_seen': min((r.first_seen for r in results if r.first_seen), default=None),
            'last_seen': max((r.last_seen for r in results if r.last_seen), default=None)
        }
        
        if context['first_seen']:
            context['first_seen'] = context['first_seen'].isoformat()
        
        if context['last_seen']:
            context['last_seen'] = context['last_seen'].isoformat()
        
        return context


# Utility functions
def detect_ioc_type(value: str) -> IOCType:
    """
    Detect the type of an indicator of compromise

    Args:
        value: String value to detect type for

    Returns:
        Detected IOCType
    """
    value = value.strip().lower()
    
    # IP address pattern
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, value):
        try:
            # Validate that it's a proper IP address
            ipaddress.ip_address(value)
            return IOCType.IP
        except ValueError:
            pass
    
    # Email pattern (check this first to avoid conflict with domain)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, value):
        return IOCType.EMAIL
    
    # URL pattern (must start with http or https)
    if value.startswith('http'):
        return IOCType.URL
    
    # Domain pattern 
    domain_pattern = r'^([\da-z]([_\w-]{0,61})[\da-z]\.)+[a-z]{2,6}$'
    if re.match(domain_pattern, value) or ('.' in value and not value.startswith('.') and '/' not in value and '@' not in value):
        return IOCType.DOMAIN
    
    # Full URL pattern (for cases with paths but no protocol)
    url_pattern = r'^([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]+)+\/?$'
    if re.match(url_pattern, value):
        return IOCType.URL
    
    # Hash patterns
    md5_pattern = r'^[a-f0-9]{32}$'
    if re.match(md5_pattern, value):
        return IOCType.MD5
    
    sha1_pattern = r'^[a-f0-9]{40}$'
    if re.match(sha1_pattern, value):
        return IOCType.SHA1
    
    sha256_pattern = r'^[a-f0-9]{64}$'
    if re.match(sha256_pattern, value):
        return IOCType.SHA256
    
    # Filename - very generic, used as last resort
    if '.' in value and not value.startswith('.') and len(value) < 256:
        return IOCType.FILENAME
    
    return IOCType.UNKNOWN

def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    """
    Check if an IP address is within a CIDR range

    Args:
        ip: IP address to check
        cidr: CIDR notation range (e.g., "192.168.1.0/24")

    Returns:
        True if IP is in range, False otherwise
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
    except ValueError:
        return False

def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent comparison

    Args:
        url: URL to normalize

    Returns:
        Normalized URL string
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    
    # Normalize hostname (lowercase, remove www. prefix)
    hostname = parsed.netloc.lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    
    # Reconstruct URL with normalized components
    normalized = f"{parsed.scheme}://{hostname}{parsed.path}"
    
    # Add query parameters if present
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized

def calculate_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate cryptographic hash of a file

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hex digest of the hash or None if error
    """
    if not os.path.isfile(file_path):
        return None
    
    try:
        if algorithm == 'md5':
            hasher = hashlib.md5()
        elif algorithm == 'sha1':
            hasher = hashlib.sha1()
        else:  # Default to sha256
            hasher = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    except Exception:
        return None

def load_config_from_file(file_path: str) -> Dict:
    """
    Load threat intelligence configuration from a file

    Args:
        file_path: Path to configuration file (JSON or YAML)

    Returns:
        Configuration dictionary
    """
    try:
        if not os.path.isfile(file_path):
            return {}
        
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                return json.load(f)
            elif file_path.endswith(('.yaml', '.yml')):
                import yaml
                return yaml.safe_load(f)
            else:
                # Try to detect format based on content
                content = f.read()
                if content.strip().startswith('{'):
                    return json.loads(content)
                else:
                    import yaml
                    return yaml.safe_load(content)
    except Exception as e:
        logging.getLogger('sharpeye.threat_intelligence').error(f"Error loading config from {file_path}: {e}")
        return {}