#!/usr/bin/env python3
"""
Unit tests for Threat Intelligence module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import os
import sys
import time
import requests
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.threat_intelligence import (
    IOCType, ThreatIntelligenceCache, IOC, ThreatIntelligenceProvider,
    MISPProvider, OTXProvider, MandiantProvider, ThreatIntelligenceManager,
    detect_ioc_type, is_ip_in_cidr, normalize_url, calculate_hash
)


class TestIOCType(unittest.TestCase):
    """Test IOCType enum"""
    
    def test_ioc_types(self):
        """Test IOC type values"""
        self.assertIsNotNone(IOCType.IP)
        self.assertIsNotNone(IOCType.DOMAIN)
        self.assertIsNotNone(IOCType.URL)
        self.assertIsNotNone(IOCType.MD5)
        self.assertIsNotNone(IOCType.SHA1)
        self.assertIsNotNone(IOCType.SHA256)
        self.assertIsNotNone(IOCType.EMAIL)
        self.assertIsNotNone(IOCType.FILENAME)
        self.assertIsNotNone(IOCType.UNKNOWN)


class TestThreatIntelligenceCache(unittest.TestCase):
    """Test ThreatIntelligenceCache class"""
    
    def setUp(self):
        """Set up test cases"""
        self.cache = ThreatIntelligenceCache(max_size=10, ttl_seconds=3600)
    
    def test_cache_set_get(self):
        """Test cache set and get operations"""
        data = {'malicious': True, 'score': 0.8}
        
        # Set item
        self.cache.set('test_key', data)
        
        # Get item
        retrieved = self.cache.get('test_key')
        self.assertEqual(retrieved, data)
    
    def test_cache_expiration(self):
        """Test cache expiration"""
        # Set item with 1 second TTL
        self.cache.set('expire_key', {'value': 'test'}, ttl_seconds=1)
        
        # Should exist immediately
        self.assertIsNotNone(self.cache.get('expire_key'))
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Should be expired
        self.assertIsNone(self.cache.get('expire_key'))
    
    def test_cache_max_size(self):
        """Test cache max size limit"""
        # Fill cache beyond max size
        for i in range(15):
            self.cache.set(f'key_{i}', {'value': i})
        
        # Cache should only have max_size items
        self.assertLessEqual(len(self.cache._cache), 10)
        
        # Oldest items should be evicted
        self.assertIsNone(self.cache.get('key_0'))
        self.assertIsNotNone(self.cache.get('key_14'))
    
    def test_cache_clear(self):
        """Test cache clearing"""
        # Add items
        self.cache.set('key1', {'value': 1})
        self.cache.set('key2', {'value': 2})
        
        # Clear cache
        self.cache.clear()
        
        # Should be empty
        self.assertIsNone(self.cache.get('key1'))
        self.assertIsNone(self.cache.get('key2'))
        self.assertEqual(len(self.cache._cache), 0)


class TestIOC(unittest.TestCase):
    """Test IOC class"""
    
    def test_ioc_creation(self):
        """Test IOC creation"""
        ioc = IOC(
            value='192.168.1.1',
            ioc_type=IOCType.IP,
            source='TestSource',
            malicious=True,
            confidence=0.9,
            tags=['malware', 'c2'],
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description='Test IOC',
            source_info={'extra': 'data'}
        )
        
        self.assertEqual(ioc.value, '192.168.1.1')
        self.assertEqual(ioc.ioc_type, IOCType.IP)
        self.assertTrue(ioc.malicious)
        self.assertEqual(ioc.confidence, 0.9)
        self.assertEqual(len(ioc.tags), 2)
    
    def test_ioc_to_dict(self):
        """Test IOC to dictionary conversion"""
        now = datetime.now()
        ioc = IOC(
            value='evil.com',
            ioc_type=IOCType.DOMAIN,
            source='TestSource',
            malicious=True,
            confidence=0.8,
            first_seen=now,
            last_seen=now
        )
        
        ioc_dict = ioc.to_dict()
        
        self.assertEqual(ioc_dict['value'], 'evil.com')
        self.assertEqual(ioc_dict['type'], 'DOMAIN')
        self.assertTrue(ioc_dict['malicious'])
        self.assertEqual(ioc_dict['confidence'], 0.8)
        self.assertIsNotNone(ioc_dict['first_seen'])
        self.assertIsNotNone(ioc_dict['last_seen'])
    
    def test_ioc_from_dict(self):
        """Test IOC from dictionary creation"""
        ioc_dict = {
            'value': 'test@evil.com',
            'type': 'EMAIL',
            'source': 'TestSource',
            'malicious': True,
            'confidence': 0.7,
            'tags': ['phishing'],
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'description': 'Phishing email',
            'source_info': {'campaign': 'test'}
        }
        
        ioc = IOC.from_dict(ioc_dict)
        
        self.assertEqual(ioc.value, 'test@evil.com')
        self.assertEqual(ioc.ioc_type, IOCType.EMAIL)
        self.assertTrue(ioc.malicious)
        self.assertEqual(ioc.confidence, 0.7)
        self.assertEqual(len(ioc.tags), 1)


class TestMISPProvider(unittest.TestCase):
    """Test MISPProvider class"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'url': 'https://misp.test.com',
            'api_key': 'test_api_key',
            'verify_ssl': False
        }
        self.provider = MISPProvider(self.config)
    
    @patch('requests.Session.request')
    def test_check_ioc_found(self, mock_request):
        """Test checking IOC that is found"""
        # Mock MISP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response': {
                'Attribute': [{
                    'id': '12345',
                    'value': '192.168.1.1',
                    'type': 'ip-dst',
                    'category': 'Network activity',
                    'to_ids': True,
                    'event_id': '999',
                    'first_seen': '2024-01-01T00:00:00Z',
                    'last_seen': '2024-01-02T00:00:00Z',
                    'Tag': [{'name': 'malware:ransomware'}]
                }]
            }
        }
        
        # Mock event response
        event_response = Mock()
        event_response.status_code = 200
        event_response.json.return_value = {
            'Event': {
                'info': 'Ransomware Campaign',
                'Tag': [{'name': 'threat-level:high'}]
            }
        }
        
        mock_request.side_effect = [mock_response, event_response]
        
        # Check IOC
        ioc = self.provider.check_ioc('192.168.1.1', IOCType.IP)
        
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc.value, '192.168.1.1')
        self.assertEqual(ioc.source, 'MISP')
        self.assertTrue(ioc.malicious)
    
    @patch('requests.Session.request')
    def test_check_ioc_not_found(self, mock_request):
        """Test checking IOC that is not found"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response': {
                'Attribute': []
            }
        }
        mock_request.return_value = mock_response
        
        ioc = self.provider.check_ioc('10.0.0.1', IOCType.IP)
        
        self.assertIsNone(ioc)
    
    @patch('requests.Session.request')
    def test_test_connection_success(self, mock_request):
        """Test successful connection test"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'version': '2.4.170'}
        mock_request.return_value = mock_response
        
        result = self.provider.test_connection()
        
        self.assertTrue(result)
    
    def test_calculate_confidence(self):
        """Test confidence calculation"""
        attribute = {
            'to_ids': True,
            'sightings_count': 5,
            'Tag': [
                {'name': 'high-confidence'},
                {'name': 'malicious'}
            ]
        }
        event_tags = ['threat-level:high']
        
        confidence = self.provider._calculate_confidence(attribute, event_tags)
        
        self.assertGreater(confidence, 0.5)
        self.assertLessEqual(confidence, 1.0)


class TestOTXProvider(unittest.TestCase):
    """Test OTXProvider class"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'api_key': 'test_otx_key'
        }
        self.provider = OTXProvider(self.config)
    
    @patch('requests.Session.request')
    def test_check_ioc_found(self, mock_request):
        """Test checking IOC that is found"""
        # Mock general response
        general_response = Mock()
        general_response.status_code = 200
        general_response.json.return_value = {
            'type': 'IPv4',
            'created': '2024-01-01T00:00:00.000',
            'modified': '2024-01-02T00:00:00.000',
            'analysis': {'malware': 5}
        }
        
        # Mock pulses response
        pulses_response = Mock()
        pulses_response.status_code = 200
        pulses_response.json.return_value = {
            'results': [
                {
                    'name': 'Malware Campaign',
                    'tags': ['malware', 'apt'],
                    'author_name': 'AlienVault'
                }
            ]
        }
        
        mock_request.side_effect = [general_response, pulses_response]
        
        ioc = self.provider.check_ioc('evil.com', IOCType.DOMAIN)
        
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc.value, 'evil.com')
        self.assertEqual(ioc.source, 'AlienVault OTX')
    
    @patch('requests.Session.request')
    def test_check_ioc_not_found(self, mock_request):
        """Test checking IOC that is not found (404)"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_request.return_value = mock_response
        
        ioc = self.provider.check_ioc('safe.com', IOCType.DOMAIN)
        
        self.assertIsNone(ioc)
    
    def test_calculate_confidence(self):
        """Test OTX confidence calculation"""
        general_data = {}
        pulses = [
            {'author_name': 'AlienVault', 'tags': ['malware']},
            {'author_name': 'community', 'tags': ['apt', 'c2']},
            {'author_name': 'OTX', 'tags': ['ransomware']}
        ]
        
        confidence = self.provider._calculate_confidence(general_data, pulses)
        
        self.assertGreater(confidence, 0)
        self.assertLessEqual(confidence, 1.0)


class TestThreatIntelligenceManager(unittest.TestCase):
    """Test ThreatIntelligenceManager class"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'cache_size': 100,
            'cache_ttl': 3600,
            'providers': {
                'misp': {
                    'enabled': False
                },
                'otx': {
                    'enabled': False
                },
                'mandiant': {
                    'enabled': False
                }
            }
        }
        self.manager = ThreatIntelligenceManager(self.config)
    
    def test_initialization(self):
        """Test manager initialization"""
        self.assertIsNotNone(self.manager)
        self.assertIsNotNone(self.manager.cache)
        self.assertEqual(len(self.manager.providers), 0)  # All disabled
    
    def test_check_ioc_no_providers(self):
        """Test checking IOC with no providers"""
        results = self.manager.check_ioc('192.168.1.1')
        self.assertEqual(len(results), 0)
    
    @patch.object(MISPProvider, 'check_ioc')
    def test_check_ioc_with_provider(self, mock_check):
        """Test checking IOC with provider"""
        # Enable MISP provider
        self.manager.providers['misp'] = MISPProvider({'enabled': True})
        
        # Mock provider response
        mock_ioc = IOC(
            value='192.168.1.1',
            ioc_type=IOCType.IP,
            source='MISP',
            malicious=True,
            confidence=0.8
        )
        mock_check.return_value = mock_ioc
        
        results = self.manager.check_ioc('192.168.1.1', IOCType.IP)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].value, '192.168.1.1')
        self.assertTrue(results[0].malicious)
    
    def test_is_malicious_single_source(self):
        """Test malicious determination with single source"""
        # Create test IOCs
        malicious_ioc = IOC(
            value='evil.com',
            ioc_type=IOCType.DOMAIN,
            source='TestSource',
            malicious=True,
            confidence=0.9
        )
        
        with patch.object(self.manager, 'check_ioc') as mock_check:
            mock_check.return_value = [malicious_ioc]
            
            result = self.manager.is_malicious('evil.com', min_confidence=0.5)
            
            self.assertTrue(result)
    
    def test_is_malicious_multiple_sources_required(self):
        """Test malicious determination requiring multiple sources"""
        # Create test IOCs from different sources
        ioc1 = IOC(
            value='evil.com',
            ioc_type=IOCType.DOMAIN,
            source='Source1',
            malicious=True,
            confidence=0.8
        )
        
        ioc2 = IOC(
            value='evil.com',
            ioc_type=IOCType.DOMAIN,
            source='Source2',
            malicious=True,
            confidence=0.7
        )
        
        with patch.object(self.manager, 'check_ioc') as mock_check:
            # Test with multiple sources
            mock_check.return_value = [ioc1, ioc2]
            result = self.manager.is_malicious('evil.com', require_multiple_sources=True)
            self.assertTrue(result)
            
            # Test with single source
            mock_check.return_value = [ioc1]
            result = self.manager.is_malicious('evil.com', require_multiple_sources=True)
            self.assertFalse(result)
    
    def test_get_ioc_context(self):
        """Test getting IOC context"""
        # Create test IOCs
        ioc1 = IOC(
            value='evil.com',
            ioc_type=IOCType.DOMAIN,
            source='MISP',
            malicious=True,
            confidence=0.9,
            tags=['malware', 'c2'],
            first_seen=datetime.now() - timedelta(days=10),
            last_seen=datetime.now()
        )
        
        ioc2 = IOC(
            value='evil.com',
            ioc_type=IOCType.DOMAIN,
            source='OTX',
            malicious=True,
            confidence=0.8,
            tags=['apt', 'c2']
        )
        
        with patch.object(self.manager, 'check_ioc') as mock_check:
            mock_check.return_value = [ioc1, ioc2]
            
            context = self.manager.get_ioc_context('evil.com')
            
            self.assertTrue(context['found'])
            self.assertTrue(context['malicious'])
            self.assertEqual(context['malicious_sources'], 2)
            self.assertEqual(context['total_sources'], 2)
            self.assertIn('malware', context['tags'])
            self.assertIn('apt', context['tags'])
            self.assertIn('c2', context['tags'])


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""
    
    def test_detect_ioc_type(self):
        """Test IOC type detection"""
        # IP addresses
        self.assertEqual(detect_ioc_type('192.168.1.1'), IOCType.IP)
        self.assertEqual(detect_ioc_type('10.0.0.1'), IOCType.IP)
        
        # Domains
        self.assertEqual(detect_ioc_type('example.com'), IOCType.DOMAIN)
        self.assertEqual(detect_ioc_type('subdomain.example.co.uk'), IOCType.DOMAIN)
        
        # URLs
        self.assertEqual(detect_ioc_type('http://example.com'), IOCType.URL)
        self.assertEqual(detect_ioc_type('https://example.com/path'), IOCType.URL)
        
        # Email
        self.assertEqual(detect_ioc_type('test@example.com'), IOCType.EMAIL)
        
        # Hashes
        self.assertEqual(detect_ioc_type('d41d8cd98f00b204e9800998ecf8427e'), IOCType.MD5)
        self.assertEqual(detect_ioc_type('da39a3ee5e6b4b0d3255bfef95601890afd80709'), IOCType.SHA1)
        self.assertEqual(detect_ioc_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), IOCType.SHA256)
        
        # Unknown
        self.assertEqual(detect_ioc_type('random string'), IOCType.UNKNOWN)
    
    def test_is_ip_in_cidr(self):
        """Test IP in CIDR range checking"""
        self.assertTrue(is_ip_in_cidr('192.168.1.100', '192.168.1.0/24'))
        self.assertFalse(is_ip_in_cidr('192.168.2.100', '192.168.1.0/24'))
        self.assertTrue(is_ip_in_cidr('10.0.0.1', '10.0.0.0/8'))
        self.assertFalse(is_ip_in_cidr('invalid', '192.168.1.0/24'))
    
    def test_normalize_url(self):
        """Test URL normalization"""
        self.assertEqual(normalize_url('example.com'), 'http://example.com')
        self.assertEqual(normalize_url('http://example.com'), 'http://example.com')
        self.assertEqual(normalize_url('https://WWW.EXAMPLE.COM'), 'https://example.com')
        self.assertEqual(normalize_url('http://example.com/path?query=1'), 'http://example.com/path?query=1')
    
    def test_calculate_hash(self):
        """Test file hash calculation"""
        # Create a temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('test content')
            temp_file = f.name
        
        try:
            # Calculate hashes
            md5_hash = calculate_hash(temp_file, 'md5')
            sha1_hash = calculate_hash(temp_file, 'sha1')
            sha256_hash = calculate_hash(temp_file, 'sha256')
            
            self.assertIsNotNone(md5_hash)
            self.assertIsNotNone(sha1_hash)
            self.assertIsNotNone(sha256_hash)
            
            # Check hash lengths
            self.assertEqual(len(md5_hash), 32)
            self.assertEqual(len(sha1_hash), 40)
            self.assertEqual(len(sha256_hash), 64)
            
            # Test non-existent file
            self.assertIsNone(calculate_hash('/non/existent/file', 'sha256'))
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()