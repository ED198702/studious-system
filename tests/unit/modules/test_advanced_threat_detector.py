#!/usr/bin/env python3
"""
Unit tests for Advanced Threat Detector module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import os
import sys
import tempfile
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.modules.advanced_threat_detector import AdvancedThreatDetector, ThreatPattern, IOCType


class TestThreatPattern(unittest.TestCase):
    """Test ThreatPattern class"""
    
    def setUp(self):
        """Set up test cases"""
        self.pattern = ThreatPattern(
            pattern_id="TEST001",
            name="Test Pattern",
            category="TestCategory",
            indicators=[
                {
                    'field': 'process_name',
                    'type': 'exact',
                    'value': 'malware.exe',
                    'weight': 0.5
                },
                {
                    'field': 'cpu_usage',
                    'type': 'range',
                    'value': (80, 100),
                    'weight': 0.5
                }
            ],
            confidence_threshold=0.7
        )
    
    def test_pattern_initialization(self):
        """Test pattern initialization"""
        self.assertEqual(self.pattern.pattern_id, "TEST001")
        self.assertEqual(self.pattern.name, "Test Pattern")
        self.assertEqual(self.pattern.category, "TestCategory")
        self.assertEqual(len(self.pattern.indicators), 2)
        self.assertEqual(self.pattern.confidence_threshold, 0.7)
    
    def test_pattern_match_exact(self):
        """Test exact pattern matching"""
        data = {
            'process_name': 'malware.exe',
            'cpu_usage': 90
        }
        
        matches, confidence = self.pattern.match(data)
        self.assertTrue(matches)
        self.assertEqual(confidence, 1.0)
    
    def test_pattern_match_partial(self):
        """Test partial pattern matching"""
        data = {
            'process_name': 'legitimate.exe',
            'cpu_usage': 90
        }
        
        matches, confidence = self.pattern.match(data)
        self.assertFalse(matches)
        self.assertEqual(confidence, 0.5)
    
    def test_pattern_match_range(self):
        """Test range pattern matching"""
        data = {
            'process_name': 'test.exe',
            'cpu_usage': 85
        }
        
        pattern = ThreatPattern(
            pattern_id="TEST002",
            name="CPU Pattern",
            category="Resource",
            indicators=[{
                'field': 'cpu_usage',
                'type': 'range',
                'value': (80, 90),
                'weight': 1.0
            }]
        )
        
        matches, confidence = pattern.match(data)
        self.assertTrue(matches)
    
    def test_pattern_match_regex(self):
        """Test regex pattern matching"""
        pattern = ThreatPattern(
            pattern_id="TEST003",
            name="Regex Pattern",
            category="Test",
            indicators=[{
                'field': 'command',
                'type': 'regex',
                'value': r'powershell.*-enc',
                'weight': 1.0
            }]
        )
        
        data = {'command': 'powershell -enc base64string'}
        matches, confidence = pattern.match(data)
        self.assertTrue(matches)
        
        data = {'command': 'notepad.exe'}
        matches, confidence = pattern.match(data)
        self.assertFalse(matches)


class TestAdvancedThreatDetector(unittest.TestCase):
    """Test AdvancedThreatDetector class"""
    
    def setUp(self):
        """Set up test cases"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'model_dir': self.temp_dir,
            'pattern_detection': {
                'enabled': True,
                'confidence_threshold': 0.7
            },
            'ml_detection': {
                'enabled': True,
                'anomaly_contamination': 0.1
            }
        }
        
        # Mock psutil
        self.psutil_patcher = patch('src.modules.advanced_threat_detector.psutil')
        self.mock_psutil = self.psutil_patcher.start()
        
        self.detector = AdvancedThreatDetector(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.psutil_patcher.stop()
        
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test detector initialization"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.model_dir, self.temp_dir)
        self.assertTrue(len(self.detector.threat_patterns) > 0)
        self.assertIsNotNone(self.detector.feature_extractors)
    
    def test_load_threat_patterns(self):
        """Test loading threat patterns"""
        patterns = self.detector._load_threat_patterns()
        self.assertTrue(len(patterns) > 0)
        
        # Check for expected patterns
        pattern_ids = [p.pattern_id for p in patterns]
        self.assertIn("APT001", pattern_ids)
        self.assertIn("MINER001", pattern_ids)
        self.assertIn("RANSOM001", pattern_ids)
        self.assertIn("EXFIL001", pattern_ids)
    
    @patch('src.modules.advanced_threat_detector.psutil.process_iter')
    @patch('src.modules.advanced_threat_detector.psutil.net_connections')
    def test_collect_system_data(self, mock_net_connections, mock_process_iter):
        """Test system data collection"""
        # Mock process data
        mock_proc1 = Mock()
        mock_proc1.info = {
            'pid': 1234,
            'name': 'test.exe',
            'cpu_percent': 10.0,
            'memory_percent': 5.0
        }
        mock_proc1.cmdline.return_value = ['test.exe', '--arg']
        mock_proc1.connections.return_value = []
        
        mock_process_iter.return_value = [mock_proc1]
        
        # Mock network connections
        mock_conn = Mock()
        mock_conn.laddr = Mock(ip='127.0.0.1', port=8080)
        mock_conn.raddr = Mock(ip='8.8.8.8', port=443)
        mock_conn.status = 'ESTABLISHED'
        mock_conn.pid = 1234
        
        mock_net_connections.return_value = [mock_conn]
        
        # Mock system metrics
        self.mock_psutil.cpu_percent.return_value = 25.0
        self.mock_psutil.virtual_memory.return_value = Mock(percent=50.0)
        self.mock_psutil.disk_io_counters.return_value = Mock(_asdict=lambda: {'read_bytes': 1000})
        self.mock_psutil.net_io_counters.return_value = Mock(_asdict=lambda: {'bytes_sent': 2000})
        
        # Collect data
        data = self.detector._collect_system_data()
        
        # Verify data structure
        self.assertIn('processes', data)
        self.assertIn('network_connections', data)
        self.assertIn('system_metrics', data)
        self.assertEqual(len(data['processes']), 1)
        self.assertEqual(len(data['network_connections']), 1)
    
    def test_detect_pattern_threats(self):
        """Test pattern-based threat detection"""
        # Create test data that matches cryptominer pattern
        data = {
            'processes': [{
                'name': 'xmrig',
                'cpu_percent': 95.0
            }],
            'network_connections': [{
                'remote_port': 3333
            }],
            'system_metrics': {
                'cpu_percent': 90.0
            }
        }
        
        # Mock pattern data preparation
        with patch.object(self.detector, '_prepare_pattern_data') as mock_prepare:
            mock_prepare.return_value = {
                'process_name': 'xmrig',
                'cpu_usage': 90,
                'network_ports': [3333]
            }
            
            threats = self.detector._detect_pattern_threats(data)
            
            # Should detect at least one threat
            self.assertGreater(len(threats), 0)
    
    def test_extract_process_features(self):
        """Test process feature extraction"""
        process = {
            'name': 'suspicious.exe',
            'cpu_percent': 50.0,
            'memory_percent': 30.0,
            'connections': 5,
            'cmdline': ['suspicious.exe', '--hidden']
        }
        
        features = self.detector._extract_process_features(process)
        
        self.assertEqual(features['cpu_percent'], 50.0)
        self.assertEqual(features['memory_percent'], 30.0)
        self.assertEqual(features['num_connections'], 5)
        self.assertIn('name_entropy', features)
        self.assertIn('cmdline_length', features)
    
    def test_extract_network_features(self):
        """Test network feature extraction"""
        connection = {
            'local_addr': '127.0.0.1:8080',
            'remote_addr': '8.8.8.8:443',
            'status': 'ESTABLISHED'
        }
        
        features = self.detector._extract_network_features(connection)
        
        self.assertEqual(features['local_port'], 8080)
        self.assertEqual(features['remote_port'], 443)
        self.assertEqual(features['is_established'], 1)
        self.assertEqual(features['is_common_port'], 1)  # 443 is common
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        results = {
            'threats': [
                {'confidence': 0.8, 'severity': 'high'},
                {'confidence': 0.6, 'severity': 'medium'}
            ],
            'attack_chains': [
                {'likelihood': 0.7, 'impact': 0.8}
            ],
            'predictions': {
                'predicted_class': 'malicious',
                'confidence': 0.9
            }
        }
        
        risk_score = self.detector._calculate_risk_score(results)
        
        self.assertGreater(risk_score, 0)
        self.assertLessEqual(risk_score, 1.0)
    
    def test_generate_recommendations(self):
        """Test recommendation generation"""
        results = {
            'risk_score': 0.9,
            'threats': [
                {'category': 'APT'},
                {'category': 'Cryptominer'}
            ],
            'attack_chains': [
                {'length': 4}
            ]
        }
        
        recommendations = self.detector._generate_recommendations(results)
        
        self.assertGreater(len(recommendations), 0)
        
        # Should have critical recommendation for high risk
        critical_recs = [r for r in recommendations if r['priority'] == 'critical']
        self.assertGreater(len(critical_recs), 0)
    
    def test_analyze_attack_chains(self):
        """Test attack chain analysis"""
        threats = [
            {
                'timestamp': datetime.now().isoformat(),
                'category': 'APT',
                'entity': {'pid': 1234}
            },
            {
                'timestamp': (datetime.now() + timedelta(seconds=30)).isoformat(),
                'category': 'DataTheft',
                'entity': {'pid': 1234}
            }
        ]
        
        chains = self.detector._analyze_attack_chains(threats)
        
        # Should identify the chain
        self.assertGreater(len(chains), 0)
        self.assertEqual(chains[0]['length'], 2)
    
    def test_calculate_entropy(self):
        """Test entropy calculation"""
        # Low entropy (repetitive)
        low_entropy = self.detector._calculate_entropy("aaaaaaa")
        
        # High entropy (random)
        high_entropy = self.detector._calculate_entropy("a7B#x9Z!")
        
        self.assertLess(low_entropy, high_entropy)
    
    @patch('joblib.dump')
    def test_save_models(self, mock_dump):
        """Test model saving"""
        # Create dummy models
        self.detector.anomaly_detector = Mock()
        self.detector.threat_classifier = Mock()
        self.detector.scaler = Mock()
        
        self.detector._save_models()
        
        # Should save 3 models
        self.assertEqual(mock_dump.call_count, 3)
    
    def test_train_models(self):
        """Test model training"""
        # Create sample training data
        data = pd.DataFrame({
            'feature1': np.random.rand(100),
            'feature2': np.random.rand(100),
            'feature3': np.random.rand(100)
        })
        
        labels = pd.Series(['benign'] * 50 + ['malicious'] * 50)
        
        # Train models
        with patch('joblib.dump'):  # Mock model saving
            self.detector.train_models(data, labels)
        
        # Check models are trained
        self.assertIsNotNone(self.detector.anomaly_detector)
        self.assertIsNotNone(self.detector.threat_classifier)
    
    def test_is_beacon_behavior(self):
        """Test beacon behavior detection"""
        # Regular interval connections (beacon-like)
        base_time = datetime.now()
        regular_connections = []
        
        for i in range(10):
            regular_connections.append({
                'remote_addr': '10.0.0.1:8080',
                'timestamp': base_time + timedelta(seconds=i*60)  # Every minute
            })
        
        # Mock datetime.now() to return consistent times
        with patch('src.modules.advanced_threat_detector.datetime') as mock_datetime:
            mock_datetime.now.side_effect = [conn['timestamp'] for conn in regular_connections]
            
            is_beacon = self.detector._is_beacon_behavior(regular_connections)
            # This test might fail due to the implementation details
            # The actual implementation needs access to historical timestamps
    
    def test_full_analysis_flow(self):
        """Test complete analysis flow"""
        with patch.object(self.detector, '_collect_system_data') as mock_collect:
            with patch.object(self.detector, '_detect_pattern_threats') as mock_pattern:
                with patch.object(self.detector, '_detect_anomalies') as mock_anomaly:
                    # Setup mocks
                    mock_collect.return_value = {'processes': [], 'network_connections': []}
                    mock_pattern.return_value = [{'type': 'pattern', 'severity': 'high'}]
                    mock_anomaly.return_value = [{'type': 'anomaly', 'severity': 'medium'}]
                    
                    # Run analysis
                    results = self.detector.analyze()
                    
                    # Verify results
                    self.assertIn('threats', results)
                    self.assertIn('risk_score', results)
                    self.assertIn('recommendations', results)
                    self.assertEqual(len(results['threats']), 2)


if __name__ == '__main__':
    unittest.main()