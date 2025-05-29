#!/usr/bin/env python3
"""
Unit tests for Container Security module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call
import json
import os
import sys
import tempfile
import shutil
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.modules.container_security import ContainerSecurityModule


class TestContainerSecurityModule(unittest.TestCase):
    """Test ContainerSecurityModule class"""
    
    def setUp(self):
        """Set up test cases"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'docker_enabled': True,
            'kubernetes_enabled': True,
            'scanner_enabled': True,
            'scanner_type': 'auto',
            'baseline_file': os.path.join(self.temp_dir, 'baseline.json'),
            'sensitive_paths': ['/etc', '/root', '/var/run/docker.sock'],
            'risky_capabilities': ['CAP_SYS_ADMIN', 'CAP_NET_ADMIN']
        }
        
        # Patch subprocess.run for command availability checks
        self.subprocess_patcher = patch('src.modules.container_security.subprocess.run')
        self.mock_subprocess = self.subprocess_patcher.start()
        
        # Mock which command for checking executables
        def mock_which_side_effect(args, **kwargs):
            mock_result = Mock()
            if 'docker' in args:
                mock_result.returncode = 0  # Docker available
            elif 'kubectl' in args:
                mock_result.returncode = 0  # Kubernetes available
            elif 'trivy' in args:
                mock_result.returncode = 0  # Trivy available
            elif 'grype' in args:
                mock_result.returncode = 1  # Grype not available
            else:
                mock_result.returncode = 1
            return mock_result
        
        self.mock_subprocess.side_effect = mock_which_side_effect
        
        self.module = ContainerSecurityModule(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.subprocess_patcher.stop()
        shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test module initialization"""
        self.assertTrue(self.module.docker_enabled)
        self.assertTrue(self.module.kubernetes_enabled)
        self.assertTrue(self.module.scanner_enabled)
        self.assertEqual(self.module.scanner_type, 'trivy')  # Auto-selected
        self.assertTrue(self.module.docker_available)
        self.assertTrue(self.module.kubernetes_available)
        self.assertTrue(self.module.trivy_available)
        self.assertFalse(self.module.grype_available)
    
    @patch('subprocess.run')
    def test_docker_container_list(self, mock_run):
        """Test getting Docker container list"""
        # Reset the mock after initialization
        mock_run.reset_mock()
        
        # Mock docker ps output
        mock_result = Mock()
        mock_result.stdout = '{"Id":"abc123","Names":["test"],"Image":"nginx","State":"running"}\n{"Id":"def456","Names":["test2"],"Image":"redis","State":"exited"}'
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        containers = self.module._get_docker_containers()
        
        self.assertEqual(len(containers), 2)
        self.assertEqual(containers[0]['Id'], 'abc123')
        self.assertEqual(containers[1]['Id'], 'def456')
    
    @patch('subprocess.run')
    def test_docker_container_details(self, mock_run):
        """Test getting Docker container details"""
        mock_run.reset_mock()
        
        # Mock docker inspect output
        container_details = {
            "Id": "abc123",
            "Config": {"User": "root"},
            "HostConfig": {
                "Privileged": True,
                "Memory": 0,
                "CapAdd": ["CAP_SYS_ADMIN"],
                "Binds": ["/etc:/host/etc:rw"]
            },
            "Mounts": [{
                "Type": "bind",
                "Source": "/etc",
                "Destination": "/host/etc",
                "RO": False
            }]
        }
        
        mock_result = Mock()
        mock_result.stdout = json.dumps([container_details])
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        details = self.module._get_docker_container_details('abc123')
        
        self.assertEqual(details['Id'], 'abc123')
        self.assertTrue(details['HostConfig']['Privileged'])
    
    def test_is_docker_container_privileged(self):
        """Test privileged container detection"""
        # Privileged container
        privileged_details = {
            'HostConfig': {'Privileged': True}
        }
        self.assertTrue(self.module._is_docker_container_privileged(privileged_details))
        
        # Non-privileged container
        normal_details = {
            'HostConfig': {'Privileged': False}
        }
        self.assertFalse(self.module._is_docker_container_privileged(normal_details))
    
    def test_docker_container_missing_limits(self):
        """Test resource limit detection"""
        # Container without limits
        no_limits = {
            'HostConfig': {
                'Memory': 0,
                'CpuShares': 0,
                'CpuQuota': -1,
                'NanoCpus': 0
            }
        }
        self.assertTrue(self.module._docker_container_missing_limits(no_limits))
        
        # Container with memory limit
        with_memory = {
            'HostConfig': {
                'Memory': 1073741824,  # 1GB
                'CpuShares': 0,
                'CpuQuota': -1,
                'NanoCpus': 0
            }
        }
        self.assertTrue(self.module._docker_container_missing_limits(with_memory))  # Still missing CPU
        
        # Container with both limits
        with_both = {
            'HostConfig': {
                'Memory': 1073741824,
                'CpuShares': 0,
                'CpuQuota': 50000,  # CPU limit set
                'CpuPeriod': 100000,
                'NanoCpus': 0
            }
        }
        self.assertFalse(self.module._docker_container_missing_limits(with_both))
    
    def test_get_docker_sensitive_mounts(self):
        """Test sensitive mount detection"""
        container_details = {
            'Mounts': [
                {
                    'Type': 'bind',
                    'Source': '/etc',
                    'Destination': '/host/etc',
                    'RO': False
                },
                {
                    'Type': 'bind',
                    'Source': '/var/run/docker.sock',
                    'Destination': '/var/run/docker.sock',
                    'RO': False
                },
                {
                    'Type': 'bind',
                    'Source': '/home/user',
                    'Destination': '/data',
                    'RO': True  # Read-only, should not be flagged
                }
            ],
            'HostConfig': {
                'Binds': []
            }
        }
        
        sensitive_mounts = self.module._get_docker_sensitive_mounts(container_details)
        
        self.assertEqual(len(sensitive_mounts), 2)
        self.assertIn('/etc', sensitive_mounts)
        self.assertIn('/var/run/docker.sock', sensitive_mounts)
    
    def test_get_docker_risky_capabilities(self):
        """Test risky capability detection"""
        container_details = {
            'HostConfig': {
                'CapAdd': ['CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_CHOWN']
            }
        }
        
        risky_caps = self.module._get_docker_risky_capabilities(container_details)
        
        self.assertEqual(len(risky_caps), 2)
        self.assertIn('CAP_SYS_ADMIN', risky_caps)
        self.assertIn('CAP_NET_ADMIN', risky_caps)
        self.assertNotIn('CAP_CHOWN', risky_caps)
    
    def test_is_docker_container_root(self):
        """Test root user detection"""
        # Running as root (no user specified)
        root_container = {
            'Config': {'User': ''}
        }
        self.assertTrue(self.module._is_docker_container_root(root_container))
        
        # Explicitly root
        explicit_root = {
            'Config': {'User': 'root'}
        }
        self.assertTrue(self.module._is_docker_container_root(explicit_root))
        
        # UID 0
        uid_zero = {
            'Config': {'User': '0'}
        }
        self.assertTrue(self.module._is_docker_container_root(uid_zero))
        
        # Non-root user
        non_root = {
            'Config': {'User': 'nginx'}
        }
        self.assertFalse(self.module._is_docker_container_root(non_root))
    
    @patch('subprocess.run')
    def test_check_docker_runtime_anomalies(self, mock_run):
        """Test Docker runtime anomaly detection"""
        mock_run.reset_mock()
        
        # Mock high CPU usage
        stats_output = {
            "CPUPerc": "95.5%",
            "MemPerc": "45.0%",
            "PIDs": "150"
        }
        
        mock_result = Mock()
        mock_result.stdout = json.dumps(stats_output)
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        # Set thresholds
        self.module.runtime_cpu_threshold = 90
        self.module.runtime_memory_threshold = 90
        self.module.runtime_process_count_threshold = 100
        
        anomalies = self.module._check_docker_runtime_anomalies('abc123', 'test_container')
        
        # Should detect high CPU and high process count
        self.assertEqual(len(anomalies), 2)
        cpu_anomaly = next((a for a in anomalies if a['metric'] == 'cpu'), None)
        self.assertIsNotNone(cpu_anomaly)
        self.assertEqual(cpu_anomaly['value'], 95.5)
    
    @patch('subprocess.run')
    def test_kubernetes_pod_list(self, mock_run):
        """Test getting Kubernetes pod list"""
        mock_run.reset_mock()
        
        # Mock kubectl output
        pods_data = {
            "items": [
                {
                    "metadata": {"name": "test-pod", "namespace": "default"},
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx",
                            "securityContext": {"privileged": True}
                        }]
                    }
                }
            ]
        }
        
        mock_result = Mock()
        mock_result.stdout = json.dumps(pods_data)
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        pods = self.module._get_kubernetes_pods()
        
        self.assertEqual(len(pods), 1)
        self.assertEqual(pods[0]['metadata']['name'], 'test-pod')
    
    def test_is_kubernetes_container_privileged(self):
        """Test Kubernetes privileged container detection"""
        privileged_context = {'privileged': True}
        self.assertTrue(self.module._is_kubernetes_container_privileged(privileged_context))
        
        normal_context = {'privileged': False}
        self.assertFalse(self.module._is_kubernetes_container_privileged(normal_context))
        
        empty_context = {}
        self.assertFalse(self.module._is_kubernetes_container_privileged(empty_context))
    
    def test_kubernetes_container_missing_limits(self):
        """Test Kubernetes resource limit detection"""
        # No resources specified
        no_resources = {}
        self.assertTrue(self.module._kubernetes_container_missing_limits(no_resources))
        
        # Resources but no limits
        no_limits = {
            'resources': {
                'requests': {'cpu': '100m', 'memory': '128Mi'}
            }
        }
        self.assertTrue(self.module._kubernetes_container_missing_limits(no_limits))
        
        # Only CPU limit
        cpu_only = {
            'resources': {
                'limits': {'cpu': '1'}
            }
        }
        self.assertTrue(self.module._kubernetes_container_missing_limits(cpu_only))
        
        # Both limits
        both_limits = {
            'resources': {
                'limits': {'cpu': '1', 'memory': '1Gi'}
            }
        }
        self.assertFalse(self.module._kubernetes_container_missing_limits(both_limits))
    
    def test_get_kubernetes_sensitive_mounts(self):
        """Test Kubernetes sensitive mount detection"""
        pod = {
            'spec': {
                'volumes': [
                    {
                        'name': 'host-etc',
                        'hostPath': {'path': '/etc'}
                    },
                    {
                        'name': 'data',
                        'emptyDir': {}
                    }
                ]
            }
        }
        
        container = {
            'volumeMounts': [
                {
                    'name': 'host-etc',
                    'mountPath': '/host/etc',
                    'readOnly': False
                },
                {
                    'name': 'data',
                    'mountPath': '/data'
                }
            ]
        }
        
        sensitive_mounts = self.module._get_kubernetes_sensitive_mounts(pod, container)
        
        self.assertEqual(len(sensitive_mounts), 1)
        self.assertIn('/etc', sensitive_mounts)
    
    def test_is_kubernetes_container_root(self):
        """Test Kubernetes root user detection"""
        # Container level non-root
        container_non_root = {'runAsNonRoot': True}
        pod_context = {}
        self.assertFalse(self.module._is_kubernetes_container_root(container_non_root, pod_context))
        
        # Container level root user
        container_root = {'runAsUser': 0}
        self.assertTrue(self.module._is_kubernetes_container_root(container_root, pod_context))
        
        # Pod level non-root
        container_empty = {}
        pod_non_root = {'runAsNonRoot': True}
        self.assertFalse(self.module._is_kubernetes_container_root(container_empty, pod_non_root))
        
        # Default (no security context)
        self.assertTrue(self.module._is_kubernetes_container_root({}, {}))
    
    @patch('subprocess.run')
    def test_scan_with_trivy(self, mock_run):
        """Test Trivy vulnerability scanning"""
        mock_run.reset_mock()
        
        # Mock Trivy output
        trivy_output = {
            "Results": [{
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-12345",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                        "Description": "Test vulnerability"
                    }
                ]
            }]
        }
        
        mock_result = Mock()
        mock_result.stdout = json.dumps(trivy_output)
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        vulnerabilities = self.module._scan_with_trivy('nginx:latest')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['id'], 'CVE-2021-12345')
        self.assertEqual(vulnerabilities[0]['severity'], 'HIGH')
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        with patch.object(self.module, 'analyze') as mock_analyze:
            mock_analyze.return_value = {
                'findings': {'privileged_containers': []},
                'stats': {'privileged_count': 0}
            }
            
            baseline = self.module.establish_baseline()
            
            self.assertIn('timestamp', baseline)
            self.assertIn('findings', baseline)
            self.assertIn('environment', baseline)
            
            # Check baseline file was created
            self.assertTrue(os.path.exists(self.module.baseline_file))
    
    def test_compare_baseline(self):
        """Test baseline comparison"""
        # Create a baseline file
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'findings': {
                'privileged_containers': [],
                'containers_without_limits': []
            },
            'environment': {}
        }
        
        os.makedirs(os.path.dirname(self.module.baseline_file), exist_ok=True)
        with open(self.module.baseline_file, 'w') as f:
            json.dump(baseline_data, f)
        
        # Mock current analysis
        with patch.object(self.module, 'analyze') as mock_analyze:
            mock_analyze.return_value = {
                'findings': {
                    'privileged_containers': [
                        {'id': 'abc123', 'name': 'new-privileged'}
                    ],
                    'containers_without_limits': []
                },
                'environment': {}
            }
            
            comparison = self.module.compare_baseline()
            
            self.assertTrue(comparison['is_anomalous'])
            self.assertEqual(comparison['new_stats']['privileged_count'], 1)
    
    @patch('subprocess.run')
    def test_full_analysis_docker(self, mock_run):
        """Test full Docker analysis"""
        # Setup mocks for the full analysis flow
        mock_run.reset_mock()
        
        # Mock responses in order
        mock_responses = []
        
        # Docker ps response
        ps_result = Mock()
        ps_result.stdout = '{"Id":"abc123","Names":["test"],"Image":"nginx","State":"running"}'
        ps_result.returncode = 0
        mock_responses.append(ps_result)
        
        # Docker inspect response
        inspect_result = Mock()
        inspect_result.stdout = json.dumps([{
            "Id": "abc123",
            "Config": {"User": "root"},
            "HostConfig": {
                "Privileged": True,
                "Memory": 0,
                "CapAdd": ["CAP_SYS_ADMIN"]
            }
        }])
        inspect_result.returncode = 0
        mock_responses.append(inspect_result)
        
        # Docker stats response
        stats_result = Mock()
        stats_result.stdout = json.dumps({
            "CPUPerc": "50%",
            "MemPerc": "30%",
            "PIDs": "10"
        })
        stats_result.returncode = 0
        mock_responses.append(stats_result)
        
        mock_run.side_effect = mock_responses
        
        # Disable Kubernetes for this test
        self.module.kubernetes_enabled = False
        self.module.scanner_enabled = False
        
        results = self.module.analyze()
        
        self.assertTrue(results['is_anomalous'])
        self.assertEqual(results['stats']['privileged_count'], 1)
        self.assertEqual(results['stats']['root_containers_count'], 1)
        self.assertEqual(results['stats']['risky_capabilities_count'], 1)
    
    def test_compare_findings(self):
        """Test finding comparison"""
        current = [
            {'id': '1', 'description': 'Finding 1'},
            {'id': '2', 'description': 'Finding 2'},
            {'id': '3', 'description': 'Finding 3'}
        ]
        
        baseline = [
            {'id': '1', 'description': 'Finding 1'},
            {'id': '2', 'description': 'Finding 2'}
        ]
        
        new_findings = self.module._compare_findings(current, baseline)
        
        self.assertEqual(len(new_findings), 1)
        self.assertEqual(new_findings[0]['id'], '3')
        self.assertTrue(new_findings[0]['is_new'])


if __name__ == '__main__':
    unittest.main()