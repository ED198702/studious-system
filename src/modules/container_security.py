#!/usr/bin/env python3
"""
Container Security Module for SharpEye
Monitors Docker and Kubernetes environments for security issues and vulnerabilities.
"""

import os
import json
import logging
import subprocess
import time
import threading
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
import shlex

class ContainerSecurityModule:
    """
    Monitors container environments for security issues and vulnerabilities.
    Supports Docker and Kubernetes environments.
    """
    
    def __init__(self, config=None):
        """Initialize with configuration"""
        self.logger = logging.getLogger('sharpeye.container_security')
        self.config = config or {}
        
        # Default configuration
        self.monitoring_interval = self.config.get('monitoring_interval', 300)  # seconds
        self.continuous_monitoring = self.config.get('continuous_monitoring', False)
        self.baseline_file = self.config.get('baseline_file', '/var/lib/sharpeye/baselines/container_security.json')
        
        # Docker configuration
        self.docker_enabled = self.config.get('docker_enabled', True)
        self.docker_executable = self.config.get('docker_executable', 'docker')
        
        # Kubernetes configuration
        self.kubernetes_enabled = self.config.get('kubernetes_enabled', True)
        self.kubernetes_executable = self.config.get('kubernetes_executable', 'kubectl')
        self.kubernetes_namespace = self.config.get('kubernetes_namespace', None)  # None for all namespaces
        
        # Container scanner configuration
        self.scanner_enabled = self.config.get('scanner_enabled', True)
        self.scanner_type = self.config.get('scanner_type', 'auto')  # auto, trivy, grype
        self.scan_severity_threshold = self.config.get('scan_severity_threshold', 'HIGH')  # CRITICAL, HIGH, MEDIUM, LOW
        
        # Container runtime security configuration
        self.runtime_security_enabled = self.config.get('runtime_security_enabled', True)
        self.runtime_cpu_threshold = self.config.get('runtime_cpu_threshold', 90)  # percent
        self.runtime_memory_threshold = self.config.get('runtime_memory_threshold', 90)  # percent
        self.runtime_process_count_threshold = self.config.get('runtime_process_count_threshold', 50)
        
        # Detection settings
        self.detect_privileged = self.config.get('detect_privileged', True)
        self.detect_no_resource_limits = self.config.get('detect_no_resource_limits', True)
        self.detect_sensitive_mounts = self.config.get('detect_sensitive_mounts', True)
        self.detect_risky_capabilities = self.config.get('detect_risky_capabilities', True)
        self.detect_root_user = self.config.get('detect_root_user', True)
        
        # Lists of sensitive paths and risky capabilities
        self.sensitive_paths = self.config.get('sensitive_paths', [
            '/', '/etc', '/var', '/usr', '/boot', '/root', '/proc', '/sys', '/dev',
            '/etc/passwd', '/etc/shadow', '/etc/ssh', '/etc/ssl', '/etc/kubernetes',
            '/var/run/docker.sock', '/var/run/crio.sock', '/var/run/containerd.sock'
        ])
        
        self.risky_capabilities = self.config.get('risky_capabilities', [
            'CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE', 'CAP_SYS_MODULE',
            'CAP_SYS_RAWIO', 'CAP_SYS_BOOT', 'CAP_NET_RAW', 'CAP_MKNOD', 'CAP_AUDIT_CONTROL',
            'CAP_SETFCAP', 'CAP_MAC_ADMIN', 'CAP_MAC_OVERRIDE', 'CAP_NET_BIND_SERVICE',
            'CAP_NET_BROADCAST', 'CAP_SYS_CHROOT', 'CAP_SYS_PACCT', 'CAP_SYS_NICE',
            'CAP_SYS_RESOURCE', 'CAP_SYS_TIME', 'CAP_WAKE_ALARM'
        ])
        
        # Check availability of tools
        self.docker_available = self._is_executable_available(self.docker_executable)
        self.kubernetes_available = self._is_executable_available(self.kubernetes_executable)
        self.trivy_available = self._is_executable_available('trivy')
        self.grype_available = self._is_executable_available('grype')
        
        # Automatically select scanner if set to auto
        if self.scanner_type == 'auto':
            if self.trivy_available:
                self.scanner_type = 'trivy'
                self.logger.info("Automatically selected Trivy for vulnerability scanning")
            elif self.grype_available:
                self.scanner_type = 'grype'
                self.logger.info("Automatically selected Grype for vulnerability scanning")
            else:
                self.scanner_type = None
                self.logger.warning("No container vulnerability scanner found. Disabling scanner functionality.")
        
        # Monitoring thread
        self.monitoring_thread = None
        self.stop_monitoring = threading.Event()
        
        # Initialize results
        self.latest_results = {}
        
        self.logger.info(f"Container Security Module initialized: Docker={'Available' if self.docker_available else 'Not Available'}, "
                         f"Kubernetes={'Available' if self.kubernetes_available else 'Not Available'}, "
                         f"Scanner={self.scanner_type if self.scanner_type else 'Not Available'}")
    
    def analyze(self) -> Dict:
        """
        Analyze container environments for security issues
        
        Returns:
            dict: Analysis results with security findings
        """
        self.logger.info("Starting container security analysis")
        
        # Container findings by category
        findings = {
            'privileged_containers': [],
            'containers_without_limits': [],
            'sensitive_mounts': [],
            'risky_capabilities': [],
            'root_containers': [],
            'vulnerabilities': [],
            'runtime_anomalies': []
        }
        
        # Docker analysis
        if self.docker_enabled and self.docker_available:
            self.logger.info("Analyzing Docker environment")
            docker_findings = self._analyze_docker()
            self._merge_findings(findings, docker_findings)
        
        # Kubernetes analysis
        if self.kubernetes_enabled and self.kubernetes_available:
            self.logger.info("Analyzing Kubernetes environment")
            k8s_findings = self._analyze_kubernetes()
            self._merge_findings(findings, k8s_findings)
        
        # Calculate statistics
        stats = {
            'privileged_count': len(findings['privileged_containers']),
            'no_limits_count': len(findings['containers_without_limits']),
            'sensitive_mounts_count': len(findings['sensitive_mounts']),
            'risky_capabilities_count': len(findings['risky_capabilities']),
            'root_containers_count': len(findings['root_containers']),
            'vulnerability_count': len(findings['vulnerabilities']),
            'runtime_anomalies_count': len(findings['runtime_anomalies'])
        }
        
        # Compile results
        results = {
            'timestamp': datetime.now().isoformat(),
            'findings': findings,
            'stats': stats,
            'is_anomalous': any(count > 0 for count in stats.values())
        }
        
        # Update latest results
        self.latest_results = results
        
        # Start continuous monitoring if enabled
        if self.continuous_monitoring and not self.monitoring_thread:
            self._start_monitoring()
        
        return results
    
    def establish_baseline(self) -> Dict:
        """
        Establish a baseline of container security for future comparison
        
        Returns:
            dict: Baseline data
        """
        self.logger.info("Establishing container security baseline")
        
        # Run initial analysis to get current state
        analysis_results = self.analyze()
        
        # Create baseline record
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'findings': analysis_results['findings'],
            'stats': analysis_results['stats'],
            'environment': self._get_environment_info()
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
        # Write baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        self.logger.info(f"Container security baseline saved to {self.baseline_file}")
        
        return baseline
    
    def compare_baseline(self) -> Dict:
        """
        Compare current container security state with baseline
        
        Returns:
            dict: Comparison results
        """
        self.logger.info("Comparing container security with baseline")
        
        # Check if baseline exists
        if not os.path.exists(self.baseline_file):
            self.logger.warning("No baseline found. Run with --establish-baseline first.")
            return {
                'error': "No baseline found",
                'is_anomalous': False
            }
        
        # Load baseline
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        # Get current state
        current_results = self.analyze()
        
        # Compare findings against baseline
        new_findings = {
            'privileged_containers': self._compare_findings(
                current_results['findings']['privileged_containers'],
                baseline['findings']['privileged_containers']
            ),
            'containers_without_limits': self._compare_findings(
                current_results['findings']['containers_without_limits'],
                baseline['findings']['containers_without_limits']
            ),
            'sensitive_mounts': self._compare_findings(
                current_results['findings']['sensitive_mounts'],
                baseline['findings']['sensitive_mounts']
            ),
            'risky_capabilities': self._compare_findings(
                current_results['findings']['risky_capabilities'],
                baseline['findings']['risky_capabilities']
            ),
            'root_containers': self._compare_findings(
                current_results['findings']['root_containers'],
                baseline['findings']['root_containers']
            ),
            'vulnerabilities': self._compare_findings(
                current_results['findings']['vulnerabilities'],
                baseline['findings']['vulnerabilities']
            ),
            'runtime_anomalies': self._compare_findings(
                current_results['findings']['runtime_anomalies'],
                baseline['findings']['runtime_anomalies']
            )
        }
        
        # Calculate statistics for new findings
        new_stats = {
            'privileged_count': len(new_findings['privileged_containers']),
            'no_limits_count': len(new_findings['containers_without_limits']),
            'sensitive_mounts_count': len(new_findings['sensitive_mounts']),
            'risky_capabilities_count': len(new_findings['risky_capabilities']),
            'root_containers_count': len(new_findings['root_containers']),
            'vulnerability_count': len(new_findings['vulnerabilities']),
            'runtime_anomalies_count': len(new_findings['runtime_anomalies'])
        }
        
        # Compare environment info
        environment_changes = self._compare_environment(
            current_results.get('environment', {}),
            baseline.get('environment', {})
        )
        
        # Finalize comparison results
        comparison = {
            'timestamp': datetime.now().isoformat(),
            'baseline_timestamp': baseline.get('timestamp'),
            'new_findings': new_findings,
            'new_stats': new_stats,
            'environment_changes': environment_changes,
            'is_anomalous': any(count > 0 for count in new_stats.values()) or len(environment_changes) > 0
        }
        
        return comparison
    
    def _analyze_docker(self) -> Dict:
        """
        Analyze Docker containers for security issues
        
        Returns:
            dict: Findings by category
        """
        findings = {
            'privileged_containers': [],
            'containers_without_limits': [],
            'sensitive_mounts': [],
            'risky_capabilities': [],
            'root_containers': [],
            'vulnerabilities': [],
            'runtime_anomalies': []
        }
        
        try:
            # Get list of running containers
            containers = self._get_docker_containers()
            if not containers:
                self.logger.info("No Docker containers found")
                return findings
            
            # Get detailed information for each container
            for container in containers:
                container_id = container.get('Id', '')
                container_name = container.get('Names', ['unknown'])[0].lstrip('/')
                image = container.get('Image', 'unknown')
                
                # Skip if container is not running
                if container.get('State') != 'running':
                    continue
                
                self.logger.debug(f"Analyzing Docker container: {container_name} ({container_id[:12]})")
                
                # Get detailed information about the container
                details = self._get_docker_container_details(container_id)
                
                # Check for privileged mode
                if self.detect_privileged and self._is_docker_container_privileged(details):
                    finding = {
                        'id': container_id[:12],
                        'name': container_name,
                        'image': image,
                        'type': 'docker',
                        'severity': 'HIGH',
                        'description': 'Container is running in privileged mode',
                        'remediation': 'Run container without --privileged flag'
                    }
                    findings['privileged_containers'].append(finding)
                    self.logger.warning(f"Privileged container detected: {container_name}")
                
                # Check for resource limits
                if self.detect_no_resource_limits and self._docker_container_missing_limits(details):
                    finding = {
                        'id': container_id[:12],
                        'name': container_name,
                        'image': image,
                        'type': 'docker',
                        'severity': 'MEDIUM',
                        'description': 'Container is running without resource limits',
                        'remediation': 'Set --memory and --cpu-shares or --cpus limits'
                    }
                    findings['containers_without_limits'].append(finding)
                    self.logger.warning(f"Container without resource limits: {container_name}")
                
                # Check for sensitive mounts
                if self.detect_sensitive_mounts:
                    sensitive_mounts = self._get_docker_sensitive_mounts(details)
                    for mount in sensitive_mounts:
                        finding = {
                            'id': container_id[:12],
                            'name': container_name,
                            'image': image,
                            'type': 'docker',
                            'severity': 'HIGH',
                            'description': f"Container has sensitive path mounted: {mount}",
                            'remediation': f"Remove mount for {mount} or use read-only mount",
                            'path': mount
                        }
                        findings['sensitive_mounts'].append(finding)
                        self.logger.warning(f"Sensitive path mounted in {container_name}: {mount}")
                
                # Check for risky capabilities
                if self.detect_risky_capabilities:
                    risky_caps = self._get_docker_risky_capabilities(details)
                    for cap in risky_caps:
                        finding = {
                            'id': container_id[:12],
                            'name': container_name,
                            'image': image,
                            'type': 'docker',
                            'severity': 'HIGH',
                            'description': f"Container has risky capability: {cap}",
                            'remediation': f"Remove {cap} capability from container",
                            'capability': cap
                        }
                        findings['risky_capabilities'].append(finding)
                        self.logger.warning(f"Risky capability in {container_name}: {cap}")
                
                # Check if running as root
                if self.detect_root_user and self._is_docker_container_root(details):
                    finding = {
                        'id': container_id[:12],
                        'name': container_name,
                        'image': image,
                        'type': 'docker',
                        'severity': 'MEDIUM',
                        'description': 'Container is running as root user',
                        'remediation': 'Use --user flag to run as non-root user or use USER directive in Dockerfile'
                    }
                    findings['root_containers'].append(finding)
                    self.logger.warning(f"Container running as root: {container_name}")
                
                # Check for runtime anomalies
                if self.runtime_security_enabled:
                    anomalies = self._check_docker_runtime_anomalies(container_id, container_name)
                    for anomaly in anomalies:
                        findings['runtime_anomalies'].append(anomaly)
            
            # Scan container images for vulnerabilities
            if self.scanner_enabled and self.scanner_type:
                for container in containers:
                    container_id = container.get('Id', '')
                    container_name = container.get('Names', ['unknown'])[0].lstrip('/')
                    image = container.get('Image', 'unknown')
                    
                    # Skip if container is not running
                    if container.get('State') != 'running':
                        continue
                    
                    image_vulnerabilities = self._scan_container_image(image, 'docker', container_id[:12], container_name)
                    findings['vulnerabilities'].extend(image_vulnerabilities)
            
        except Exception as e:
            self.logger.error(f"Error analyzing Docker environment: {e}")
        
        return findings
    
    def _analyze_kubernetes(self) -> Dict:
        """
        Analyze Kubernetes pods for security issues
        
        Returns:
            dict: Findings by category
        """
        findings = {
            'privileged_containers': [],
            'containers_without_limits': [],
            'sensitive_mounts': [],
            'risky_capabilities': [],
            'root_containers': [],
            'vulnerabilities': [],
            'runtime_anomalies': []
        }
        
        try:
            # Get list of pods
            pods = self._get_kubernetes_pods()
            if not pods:
                self.logger.info("No Kubernetes pods found")
                return findings
            
            # Get detailed information for each pod
            for pod in pods:
                pod_name = pod.get('metadata', {}).get('name', 'unknown')
                namespace = pod.get('metadata', {}).get('namespace', 'default')
                
                # Get containers in the pod
                containers = pod.get('spec', {}).get('containers', [])
                if not containers:
                    continue
                
                self.logger.debug(f"Analyzing Kubernetes pod: {pod_name} in namespace {namespace}")
                
                # Security context at pod level
                pod_security_context = pod.get('spec', {}).get('securityContext', {})
                
                # Check each container in the pod
                for container in containers:
                    container_name = container.get('name', 'unknown')
                    image = container.get('image', 'unknown')
                    container_id = f"{namespace}/{pod_name}/{container_name}"
                    
                    # Container security context
                    security_context = container.get('securityContext', {})
                    
                    # Check for privileged mode
                    if self.detect_privileged and self._is_kubernetes_container_privileged(security_context):
                        finding = {
                            'id': container_id,
                            'name': container_name,
                            'pod': pod_name,
                            'namespace': namespace,
                            'image': image,
                            'type': 'kubernetes',
                            'severity': 'HIGH',
                            'description': 'Container is running in privileged mode',
                            'remediation': 'Remove privileged: true from securityContext'
                        }
                        findings['privileged_containers'].append(finding)
                        self.logger.warning(f"Privileged container detected in Kubernetes: {pod_name}/{container_name}")
                    
                    # Check for resource limits
                    if self.detect_no_resource_limits and self._kubernetes_container_missing_limits(container):
                        finding = {
                            'id': container_id,
                            'name': container_name,
                            'pod': pod_name,
                            'namespace': namespace,
                            'image': image,
                            'type': 'kubernetes',
                            'severity': 'MEDIUM',
                            'description': 'Container is running without resource limits',
                            'remediation': 'Set resources.limits.cpu and resources.limits.memory'
                        }
                        findings['containers_without_limits'].append(finding)
                        self.logger.warning(f"Container without resource limits in Kubernetes: {pod_name}/{container_name}")
                    
                    # Check for sensitive volume mounts
                    if self.detect_sensitive_mounts:
                        sensitive_mounts = self._get_kubernetes_sensitive_mounts(pod, container)
                        for mount in sensitive_mounts:
                            finding = {
                                'id': container_id,
                                'name': container_name,
                                'pod': pod_name,
                                'namespace': namespace,
                                'image': image,
                                'type': 'kubernetes',
                                'severity': 'HIGH',
                                'description': f"Container has sensitive path mounted: {mount}",
                                'remediation': f"Remove hostPath volume mount for {mount} or use readOnly: true",
                                'path': mount
                            }
                            findings['sensitive_mounts'].append(finding)
                            self.logger.warning(f"Sensitive path mounted in Kubernetes: {pod_name}/{container_name}: {mount}")
                    
                    # Check for risky capabilities
                    if self.detect_risky_capabilities:
                        risky_caps = self._get_kubernetes_risky_capabilities(security_context)
                        for cap in risky_caps:
                            finding = {
                                'id': container_id,
                                'name': container_name,
                                'pod': pod_name,
                                'namespace': namespace,
                                'image': image,
                                'type': 'kubernetes',
                                'severity': 'HIGH',
                                'description': f"Container has risky capability: {cap}",
                                'remediation': f"Remove {cap} from securityContext.capabilities.add",
                                'capability': cap
                            }
                            findings['risky_capabilities'].append(finding)
                            self.logger.warning(f"Risky capability in Kubernetes: {pod_name}/{container_name}: {cap}")
                    
                    # Check if running as root
                    if self.detect_root_user and self._is_kubernetes_container_root(security_context, pod_security_context):
                        finding = {
                            'id': container_id,
                            'name': container_name,
                            'pod': pod_name,
                            'namespace': namespace,
                            'image': image,
                            'type': 'kubernetes',
                            'severity': 'MEDIUM',
                            'description': 'Container is running as root user',
                            'remediation': 'Set securityContext.runAsNonRoot: true or runAsUser to non-zero value'
                        }
                        findings['root_containers'].append(finding)
                        self.logger.warning(f"Container running as root in Kubernetes: {pod_name}/{container_name}")
                    
                    # Check for runtime anomalies
                    if self.runtime_security_enabled:
                        anomalies = self._check_kubernetes_runtime_anomalies(namespace, pod_name, container_name)
                        for anomaly in anomalies:
                            findings['runtime_anomalies'].append(anomaly)
                    
                    # Scan container images for vulnerabilities
                    if self.scanner_enabled and self.scanner_type:
                        image_vulnerabilities = self._scan_container_image(
                            image, 'kubernetes', container_id, container_name,
                            namespace=namespace, pod=pod_name
                        )
                        findings['vulnerabilities'].extend(image_vulnerabilities)
            
        except Exception as e:
            self.logger.error(f"Error analyzing Kubernetes environment: {e}")
        
        return findings
    
    def _get_docker_containers(self) -> List[Dict]:
        """
        Get list of Docker containers
        
        Returns:
            list: Docker container details
        """
        try:
            cmd = [self.docker_executable, 'ps', '-a', '--format', '{{json .}}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        container = json.loads(line)
                        containers.append(container)
                    except json.JSONDecodeError:
                        self.logger.warning(f"Failed to parse Docker container JSON: {line}")
            
            return containers
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get Docker containers: {e}")
            return []
    
    def _get_docker_container_details(self, container_id: str) -> Dict:
        """
        Get detailed information about a Docker container
        
        Args:
            container_id: Docker container ID
            
        Returns:
            dict: Container details
        """
        try:
            cmd = [self.docker_executable, 'inspect', container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            details = json.loads(result.stdout)
            
            if details and isinstance(details, list):
                return details[0]
            return {}
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get Docker container details for {container_id}: {e}")
            return {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Docker container details for {container_id}: {e}")
            return {}
    
    def _is_docker_container_privileged(self, container_details: Dict) -> bool:
        """
        Check if a Docker container is running in privileged mode
        
        Args:
            container_details: Container details from Docker inspect
            
        Returns:
            bool: True if container is privileged
        """
        host_config = container_details.get('HostConfig', {})
        return host_config.get('Privileged', False)
    
    def _docker_container_missing_limits(self, container_details: Dict) -> bool:
        """
        Check if a Docker container is missing resource limits
        
        Args:
            container_details: Container details from Docker inspect
            
        Returns:
            bool: True if container is missing CPU or memory limits
        """
        host_config = container_details.get('HostConfig', {})
        
        # Check if memory limit is set (0 means no limit)
        memory_limit = host_config.get('Memory', 0)
        
        # Check if CPU limit is set
        # Docker can use --cpu-shares, --cpus, or --cpu-quota/--cpu-period
        cpu_shares = host_config.get('CpuShares', 0)  # Default is 0 (unlimited)
        cpu_quota = host_config.get('CpuQuota', -1)   # Default is -1 (unlimited)
        cpu_period = host_config.get('CpuPeriod', 0)  # Default is 100000
        
        # cpu_nano_cpus is used when --cpus flag is set
        nano_cpus = host_config.get('NanoCpus', 0)
        
        # If any of these are set to a limiting value, we consider CPU limits to be set
        cpu_limited = (
            (cpu_shares != 0 and cpu_shares != 1024) or  # 1024 is the default weight
            cpu_quota > 0 or  # Any positive quota is a limit
            nano_cpus > 0     # Any positive nano_cpus is a limit
        )
        
        # Container is missing limits if either memory or CPU limits are missing
        return memory_limit == 0 or not cpu_limited
    
    def _get_docker_sensitive_mounts(self, container_details: Dict) -> List[str]:
        """
        Get sensitive paths mounted in Docker container
        
        Args:
            container_details: Container details from Docker inspect
            
        Returns:
            list: List of sensitive host paths mounted in container
        """
        sensitive_mounts = []
        
        # Check mounts
        mounts = container_details.get('Mounts', [])
        for mount in mounts:
            if mount.get('Type') == 'bind':
                source = mount.get('Source', '')
                
                # Check if source path is sensitive
                for sensitive_path in self.sensitive_paths:
                    if source == sensitive_path or source.startswith(f"{sensitive_path}/"):
                        read_only = mount.get('RO', False)
                        if not read_only:  # If the mount is not read-only, it's a higher risk
                            sensitive_mounts.append(source)
        
        # Check binds as well (older Docker versions)
        host_config = container_details.get('HostConfig', {})
        binds = host_config.get('Binds', [])
        for bind in binds:
            parts = bind.split(':')
            if len(parts) >= 2:
                source = parts[0]
                
                # Check if source path is sensitive
                for sensitive_path in self.sensitive_paths:
                    if source == sensitive_path or source.startswith(f"{sensitive_path}/"):
                        # Check if it's read-only (parts[2] should contain "ro" if read-only)
                        read_only = len(parts) > 2 and 'ro' in parts[2]
                        if not read_only:
                            sensitive_mounts.append(source)
        
        return sensitive_mounts
    
    def _get_docker_risky_capabilities(self, container_details: Dict) -> List[str]:
        """
        Get risky capabilities granted to Docker container
        
        Args:
            container_details: Container details from Docker inspect
            
        Returns:
            list: List of risky capabilities
        """
        risky_caps = []
        
        host_config = container_details.get('HostConfig', {})
        cap_add = host_config.get('CapAdd', [])
        
        # Check if any risky capabilities are added
        for cap in cap_add:
            if cap in self.risky_capabilities:
                risky_caps.append(cap)
        
        return risky_caps
    
    def _is_docker_container_root(self, container_details: Dict) -> bool:
        """
        Check if Docker container is running as root
        
        Args:
            container_details: Container details from Docker inspect
            
        Returns:
            bool: True if container is running as root
        """
        config = container_details.get('Config', {})
        user = config.get('User', '')
        
        # If user is not specified or is "0" or "root", container is running as root
        return not user or user == '0' or user == 'root'
    
    def _check_docker_runtime_anomalies(self, container_id: str, container_name: str) -> List[Dict]:
        """
        Check for runtime anomalies in Docker container
        
        Args:
            container_id: Docker container ID
            container_name: Docker container name
            
        Returns:
            list: List of runtime anomalies found
        """
        anomalies = []
        
        try:
            # Get container stats
            cmd = [self.docker_executable, 'stats', container_id, '--no-stream', '--format', '{{json .}}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if not result.stdout.strip():
                return anomalies
            
            stats = json.loads(result.stdout.strip())
            
            # Parse CPU usage
            cpu_usage = stats.get('CPUPerc', '0%')
            cpu_percentage = float(cpu_usage.strip('%'))
            
            # Parse memory usage
            memory_usage = stats.get('MemPerc', '0%')
            memory_percentage = float(memory_usage.strip('%'))
            
            # Get process count
            process_count = int(stats.get('PIDs', '0'))
            
            # Check for high CPU usage
            if cpu_percentage > self.runtime_cpu_threshold:
                anomaly = {
                    'id': container_id[:12],
                    'name': container_name,
                    'type': 'docker',
                    'severity': 'MEDIUM',
                    'description': f'Container using high CPU: {cpu_percentage:.1f}%',
                    'remediation': 'Check for intensive processes or potential cryptomining',
                    'metric': 'cpu',
                    'value': cpu_percentage
                }
                anomalies.append(anomaly)
                self.logger.warning(f"High CPU usage in container {container_name}: {cpu_percentage:.1f}%")
            
            # Check for high memory usage
            if memory_percentage > self.runtime_memory_threshold:
                anomaly = {
                    'id': container_id[:12],
                    'name': container_name,
                    'type': 'docker',
                    'severity': 'MEDIUM',
                    'description': f'Container using high memory: {memory_percentage:.1f}%',
                    'remediation': 'Check for memory leaks or resource constraints',
                    'metric': 'memory',
                    'value': memory_percentage
                }
                anomalies.append(anomaly)
                self.logger.warning(f"High memory usage in container {container_name}: {memory_percentage:.1f}%")
            
            # Check for high process count
            if process_count > self.runtime_process_count_threshold:
                anomaly = {
                    'id': container_id[:12],
                    'name': container_name,
                    'type': 'docker',
                    'severity': 'MEDIUM',
                    'description': f'Container has high process count: {process_count}',
                    'remediation': 'Check for process explosion or fork bombs',
                    'metric': 'processes',
                    'value': process_count
                }
                anomalies.append(anomaly)
                self.logger.warning(f"High process count in container {container_name}: {process_count}")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get Docker container stats for {container_id}: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Docker container stats for {container_id}: {e}")
        
        return anomalies
    
    def _get_kubernetes_pods(self) -> List[Dict]:
        """
        Get list of Kubernetes pods
        
        Returns:
            list: Kubernetes pod details
        """
        try:
            # Construct base command
            cmd = [self.kubernetes_executable, 'get', 'pods', '-o', 'json']
            
            # Add namespace flag if specified
            if self.kubernetes_namespace:
                cmd.extend(['-n', self.kubernetes_namespace])
            else:
                cmd.append('--all-namespaces')
            
            # Run command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse JSON
            data = json.loads(result.stdout)
            return data.get('items', [])
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get Kubernetes pods: {e}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Kubernetes pods data: {e}")
            return []
    
    def _is_kubernetes_container_privileged(self, security_context: Dict) -> bool:
        """
        Check if a Kubernetes container is running in privileged mode
        
        Args:
            security_context: Container security context
            
        Returns:
            bool: True if container is privileged
        """
        return security_context.get('privileged', False)
    
    def _kubernetes_container_missing_limits(self, container: Dict) -> bool:
        """
        Check if a Kubernetes container is missing resource limits
        
        Args:
            container: Kubernetes container spec
            
        Returns:
            bool: True if container is missing CPU or memory limits
        """
        resources = container.get('resources', {})
        limits = resources.get('limits', {})
        
        # Check if CPU and memory limits are set
        return 'cpu' not in limits or 'memory' not in limits
    
    def _get_kubernetes_sensitive_mounts(self, pod: Dict, container: Dict) -> List[str]:
        """
        Get sensitive paths mounted in Kubernetes container
        
        Args:
            pod: Kubernetes pod spec
            container: Kubernetes container spec
            
        Returns:
            list: List of sensitive host paths
        """
        sensitive_mounts = []
        
        # Get volumes from pod spec
        volumes = pod.get('spec', {}).get('volumes', [])
        volume_map = {}
        
        # Map volume names to their sources
        for volume in volumes:
            name = volume.get('name', '')
            
            # Check for hostPath volumes
            if 'hostPath' in volume:
                host_path = volume['hostPath'].get('path', '')
                volume_map[name] = host_path
        
        # Check container volume mounts
        volume_mounts = container.get('volumeMounts', [])
        for mount in volume_mounts:
            volume_name = mount.get('name', '')
            
            # If this volume is a hostPath
            if volume_name in volume_map:
                host_path = volume_map[volume_name]
                
                # Check if path is sensitive
                for sensitive_path in self.sensitive_paths:
                    if host_path == sensitive_path or host_path.startswith(f"{sensitive_path}/"):
                        read_only = mount.get('readOnly', False)
                        if not read_only:  # If the mount is not read-only, it's a higher risk
                            sensitive_mounts.append(host_path)
        
        return sensitive_mounts
    
    def _get_kubernetes_risky_capabilities(self, security_context: Dict) -> List[str]:
        """
        Get risky capabilities granted to Kubernetes container
        
        Args:
            security_context: Container security context
            
        Returns:
            list: List of risky capabilities
        """
        risky_caps = []
        
        # Get added capabilities
        capabilities = security_context.get('capabilities', {})
        add_capabilities = capabilities.get('add', [])
        
        # Check if any risky capabilities are added
        for cap in add_capabilities:
            if cap in self.risky_capabilities:
                risky_caps.append(cap)
        
        return risky_caps
    
    def _is_kubernetes_container_root(self, container_security_context: Dict, pod_security_context: Dict) -> bool:
        """
        Check if Kubernetes container is running as root
        
        Args:
            container_security_context: Container security context
            pod_security_context: Pod security context
            
        Returns:
            bool: True if container is running as root
        """
        # Check container-level security context first
        run_as_non_root = container_security_context.get('runAsNonRoot', None)
        if run_as_non_root is not None:
            return not run_as_non_root
        
        run_as_user = container_security_context.get('runAsUser', None)
        if run_as_user is not None:
            return run_as_user == 0
        
        # If not specified at container level, check pod level
        run_as_non_root = pod_security_context.get('runAsNonRoot', None)
        if run_as_non_root is not None:
            return not run_as_non_root
        
        run_as_user = pod_security_context.get('runAsUser', None)
        if run_as_user is not None:
            return run_as_user == 0
        
        # Default is root if not specified
        return True
    
    def _check_kubernetes_runtime_anomalies(self, namespace: str, pod_name: str, container_name: str) -> List[Dict]:
        """
        Check for runtime anomalies in Kubernetes container
        
        Args:
            namespace: Kubernetes namespace
            pod_name: Kubernetes pod name
            container_name: Kubernetes container name
            
        Returns:
            list: List of runtime anomalies found
        """
        anomalies = []
        
        try:
            # Get container resource usage with metrics API
            cmd = [
                self.kubernetes_executable, 'top', 'pod', pod_name,
                '-n', namespace, '--containers', '--use-protocol-buffers'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # If command failed, metrics API might not be available
            if result.returncode != 0:
                return anomalies
            
            # Parse output
            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:
                return anomalies
            
            # Find the line for our container
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 5:
                    # Format: POD NAME    CONTAINER NAME    CPU    MEMORY    ...
                    if parts[1] == container_name:
                        # Extract CPU and memory usage
                        cpu_usage = parts[2]
                        memory_usage = parts[3]
                        
                        # Parse CPU usage (remove 'm' suffix for millicores)
                        cpu_value = float(cpu_usage.rstrip('m'))
                        cpu_percentage = cpu_value / 10  # 1000m = 1 CPU = 100%
                        
                        # Parse memory usage
                        memory_value = float(memory_usage.rstrip('Mi'))
                        
                        # Get process count using exec
                        process_count = self._get_kubernetes_process_count(namespace, pod_name, container_name)
                        
                        # Check for high CPU usage
                        if cpu_percentage > self.runtime_cpu_threshold:
                            anomaly = {
                                'id': f"{namespace}/{pod_name}/{container_name}",
                                'name': container_name,
                                'pod': pod_name,
                                'namespace': namespace,
                                'type': 'kubernetes',
                                'severity': 'MEDIUM',
                                'description': f'Container using high CPU: {cpu_percentage:.1f}%',
                                'remediation': 'Check for intensive processes or potential cryptomining',
                                'metric': 'cpu',
                                'value': cpu_percentage
                            }
                            anomalies.append(anomaly)
                            self.logger.warning(f"High CPU usage in container {namespace}/{pod_name}/{container_name}: {cpu_percentage:.1f}%")
                        
                        # We don't have percentage for memory, only absolute value,
                        # but we can still check for high process count
                        if process_count > self.runtime_process_count_threshold:
                            anomaly = {
                                'id': f"{namespace}/{pod_name}/{container_name}",
                                'name': container_name,
                                'pod': pod_name,
                                'namespace': namespace,
                                'type': 'kubernetes',
                                'severity': 'MEDIUM',
                                'description': f'Container has high process count: {process_count}',
                                'remediation': 'Check for process explosion or fork bombs',
                                'metric': 'processes',
                                'value': process_count
                            }
                            anomalies.append(anomaly)
                            self.logger.warning(f"High process count in container {namespace}/{pod_name}/{container_name}: {process_count}")
                        
                        break
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get Kubernetes container stats for {namespace}/{pod_name}/{container_name}: {e}")
        
        return anomalies
    
    def _get_kubernetes_process_count(self, namespace: str, pod_name: str, container_name: str) -> int:
        """
        Get process count in Kubernetes container
        
        Args:
            namespace: Kubernetes namespace
            pod_name: Kubernetes pod name
            container_name: Kubernetes container name
            
        Returns:
            int: Process count
        """
        try:
            # Use exec to run ps command in container
            cmd = [
                self.kubernetes_executable, 'exec', pod_name,
                '-n', namespace, '-c', container_name,
                '--', 'ps', 'aux', '--no-header'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # If command failed, container might not have ps
            if result.returncode != 0:
                return 0
            
            # Count lines for process count
            processes = result.stdout.strip().split('\n')
            return len(processes)
            
        except subprocess.CalledProcessError:
            return 0
    
    def _scan_container_image(self, image: str, container_type: str, container_id: str, 
                             container_name: str, namespace: str = None, pod: str = None) -> List[Dict]:
        """
        Scan container image for vulnerabilities
        
        Args:
            image: Container image name
            container_type: 'docker' or 'kubernetes'
            container_id: Container ID
            container_name: Container name
            namespace: Kubernetes namespace (for Kubernetes containers)
            pod: Kubernetes pod name (for Kubernetes containers)
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if not self.scanner_type:
            return vulnerabilities
        
        try:
            # Choose scanner based on configuration
            if self.scanner_type == 'trivy' and self.trivy_available:
                vulns = self._scan_with_trivy(image)
            elif self.scanner_type == 'grype' and self.grype_available:
                vulns = self._scan_with_grype(image)
            else:
                self.logger.warning(f"Requested scanner {self.scanner_type} is not available")
                return vulnerabilities
            
            # Add container details to each vulnerability
            for vuln in vulns:
                vuln['container_id'] = container_id
                vuln['container_name'] = container_name
                vuln['type'] = container_type
                
                if container_type == 'kubernetes':
                    vuln['namespace'] = namespace
                    vuln['pod'] = pod
                
                vulnerabilities.append(vuln)
            
        except Exception as e:
            self.logger.error(f"Error scanning image {image}: {e}")
        
        return vulnerabilities
    
    def _scan_with_trivy(self, image: str) -> List[Dict]:
        """
        Scan container image with Trivy
        
        Args:
            image: Container image name
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Map severity threshold to Trivy format
            severity_levels = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            threshold_index = severity_levels.index(self.scan_severity_threshold)
            allowed_severities = severity_levels[threshold_index:]
            
            severity_flag = ','.join(allowed_severities)
            
            # Run Trivy scan
            cmd = [
                'trivy', 'image', '--no-progress', '--quiet',
                '--format', 'json', '--severity', severity_flag, image
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            scan_results = json.loads(result.stdout)
            
            # Process results
            for result in scan_results.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    # Extract details
                    vulnerability = {
                        'id': vuln.get('VulnerabilityID', 'unknown'),
                        'package': vuln.get('PkgName', 'unknown'),
                        'version': vuln.get('InstalledVersion', 'unknown'),
                        'fixed_version': vuln.get('FixedVersion', ''),
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'description': vuln.get('Description', ''),
                        'references': vuln.get('References', []),
                        'source': 'Trivy',
                        'image': image,
                        'remediation': f"Update {vuln.get('PkgName', 'package')} to version {vuln.get('FixedVersion', 'latest')}"
                    }
                    
                    vulnerabilities.append(vulnerability)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to scan image {image} with Trivy: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Trivy scan results for {image}: {e}")
        
        return vulnerabilities
    
    def _scan_with_grype(self, image: str) -> List[Dict]:
        """
        Scan container image with Grype
        
        Args:
            image: Container image name
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Map severity threshold to Grype format
            severity_levels = ['negligible', 'low', 'medium', 'high', 'critical']
            threshold_index = max(0, ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(self.scan_severity_threshold))
            allowed_severities = severity_levels[threshold_index:]
            
            # Run Grype scan
            cmd = [
                'grype', image, '-o', 'json', 
                '--fail-on', ','.join(allowed_severities)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            scan_results = json.loads(result.stdout)
            
            # Process results
            for match in scan_results.get('matches', []):
                vuln = match.get('vulnerability', {})
                artifact = match.get('artifact', {})
                
                # Skip if severity is below threshold
                severity = vuln.get('severity', '').upper()
                if severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] or severity_levels.index(vuln.get('severity', '').lower()) < threshold_index:
                    continue
                
                # Extract details
                vulnerability = {
                    'id': vuln.get('id', 'unknown'),
                    'package': artifact.get('name', 'unknown'),
                    'version': artifact.get('version', 'unknown'),
                    'fixed_version': match.get('fixedInVersion', ''),
                    'severity': severity,
                    'description': vuln.get('description', ''),
                    'references': vuln.get('references', []),
                    'source': 'Grype',
                    'image': image,
                    'remediation': f"Update {artifact.get('name', 'package')} to version {match.get('fixedInVersion', 'latest')}"
                }
                
                vulnerabilities.append(vulnerability)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to scan image {image} with Grype: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Grype scan results for {image}: {e}")
        
        return vulnerabilities
    
    def _merge_findings(self, target: Dict, source: Dict) -> None:
        """
        Merge findings from source into target
        
        Args:
            target: Target dictionary to merge into
            source: Source dictionary to merge from
        """
        for key, items in source.items():
            if key in target:
                target[key].extend(items)
    
    def _compare_findings(self, current_findings: List[Dict], baseline_findings: List[Dict]) -> List[Dict]:
        """
        Compare current findings against baseline to identify new findings
        
        Args:
            current_findings: Current findings
            baseline_findings: Baseline findings
            
        Returns:
            list: New findings not in baseline
        """
        # Create a set of identifiers from baseline
        baseline_ids = set()
        
        for finding in baseline_findings:
            # Create a unique identifier based on finding type
            if finding.get('type') == 'docker':
                identifier = f"docker:{finding.get('id')}:{finding.get('description')}"
            elif finding.get('type') == 'kubernetes':
                identifier = f"kubernetes:{finding.get('namespace')}:{finding.get('pod')}:{finding.get('name')}:{finding.get('description')}"
            else:
                identifier = str(finding)  # Fallback
            
            baseline_ids.add(identifier)
        
        # Find new findings not in baseline
        new_findings = []
        
        for finding in current_findings:
            # Create a unique identifier based on finding type
            if finding.get('type') == 'docker':
                identifier = f"docker:{finding.get('id')}:{finding.get('description')}"
            elif finding.get('type') == 'kubernetes':
                identifier = f"kubernetes:{finding.get('namespace')}:{finding.get('pod')}:{finding.get('name')}:{finding.get('description')}"
            else:
                identifier = str(finding)  # Fallback
            
            if identifier not in baseline_ids:
                finding['is_new'] = True
                new_findings.append(finding)
        
        return new_findings
    
    def _get_environment_info(self) -> Dict:
        """
        Get information about container environment
        
        Returns:
            dict: Environment information
        """
        info = {
            'docker': {
                'available': self.docker_available,
                'version': self._get_docker_version(),
                'containers': self._count_docker_containers()
            },
            'kubernetes': {
                'available': self.kubernetes_available,
                'version': self._get_kubernetes_version(),
                'pods': self._count_kubernetes_pods()
            },
            'scanner': {
                'type': self.scanner_type,
                'trivy_available': self.trivy_available,
                'grype_available': self.grype_available
            }
        }
        
        return info
    
    def _compare_environment(self, current: Dict, baseline: Dict) -> List[Dict]:
        """
        Compare current environment with baseline
        
        Args:
            current: Current environment info
            baseline: Baseline environment info
            
        Returns:
            list: List of significant changes
        """
        changes = []
        
        # Compare Docker info
        if current.get('docker', {}).get('available') != baseline.get('docker', {}).get('available'):
            changes.append({
                'component': 'docker',
                'property': 'available',
                'baseline': baseline.get('docker', {}).get('available'),
                'current': current.get('docker', {}).get('available')
            })
        
        if current.get('docker', {}).get('version') != baseline.get('docker', {}).get('version'):
            changes.append({
                'component': 'docker',
                'property': 'version',
                'baseline': baseline.get('docker', {}).get('version'),
                'current': current.get('docker', {}).get('version')
            })
        
        # Compare Kubernetes info
        if current.get('kubernetes', {}).get('available') != baseline.get('kubernetes', {}).get('available'):
            changes.append({
                'component': 'kubernetes',
                'property': 'available',
                'baseline': baseline.get('kubernetes', {}).get('available'),
                'current': current.get('kubernetes', {}).get('available')
            })
        
        if current.get('kubernetes', {}).get('version') != baseline.get('kubernetes', {}).get('version'):
            changes.append({
                'component': 'kubernetes',
                'property': 'version',
                'baseline': baseline.get('kubernetes', {}).get('version'),
                'current': current.get('kubernetes', {}).get('version')
            })
        
        # Compare scanner info
        if current.get('scanner', {}).get('type') != baseline.get('scanner', {}).get('type'):
            changes.append({
                'component': 'scanner',
                'property': 'type',
                'baseline': baseline.get('scanner', {}).get('type'),
                'current': current.get('scanner', {}).get('type')
            })
        
        return changes
    
    def _get_docker_version(self) -> str:
        """
        Get Docker version
        
        Returns:
            str: Docker version string
        """
        if not self.docker_available:
            return "unavailable"
        
        try:
            cmd = [self.docker_executable, 'version', '--format', '{{.Server.Version}}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "unknown"
    
    def _get_kubernetes_version(self) -> str:
        """
        Get Kubernetes version
        
        Returns:
            str: Kubernetes version string
        """
        if not self.kubernetes_available:
            return "unavailable"
        
        try:
            cmd = [self.kubernetes_executable, 'version', '--client', '--output=json']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            try:
                version_info = json.loads(result.stdout)
                return version_info.get('clientVersion', {}).get('gitVersion', 'unknown')
            except json.JSONDecodeError:
                return "unknown"
                
        except subprocess.CalledProcessError:
            return "unknown"
    
    def _count_docker_containers(self) -> int:
        """
        Count running Docker containers
        
        Returns:
            int: Number of running containers
        """
        if not self.docker_available:
            return 0
        
        try:
            cmd = [self.docker_executable, 'ps', '--quiet']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            containers = result.stdout.strip().split('\n')
            return len([c for c in containers if c])
        except subprocess.CalledProcessError:
            return 0
    
    def _count_kubernetes_pods(self) -> int:
        """
        Count running Kubernetes pods
        
        Returns:
            int: Number of running pods
        """
        if not self.kubernetes_available:
            return 0
        
        try:
            # Construct base command
            cmd = [self.kubernetes_executable, 'get', 'pods', '--no-headers']
            
            # Add namespace flag if specified
            if self.kubernetes_namespace:
                cmd.extend(['-n', self.kubernetes_namespace])
            else:
                cmd.append('--all-namespaces')
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            pods = result.stdout.strip().split('\n')
            return len([p for p in pods if p])
        except subprocess.CalledProcessError:
            return 0
    
    def _is_executable_available(self, executable: str) -> bool:
        """
        Check if an executable is available
        
        Args:
            executable: Name of executable to check
            
        Returns:
            bool: True if executable is available
        """
        try:
            # Use which to find the executable path
            result = subprocess.run(['which', executable], capture_output=True, text=True)
            return result.returncode == 0
        except subprocess.SubprocessError:
            return False
    
    def _start_monitoring(self) -> None:
        """
        Start continuous monitoring for container security issues
        """
        self.stop_monitoring.clear()
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="ContainerSecurityMonitor"
        )
        self.monitoring_thread.start()
        self.logger.info("Started continuous container security monitoring")
    
    def _stop_monitoring(self) -> None:
        """
        Stop the continuous monitoring thread
        """
        if self.monitoring_thread:
            self.stop_monitoring.set()
            self.monitoring_thread.join(timeout=5)
            self.monitoring_thread = None
            self.logger.info("Stopped continuous container security monitoring")
    
    def _monitoring_loop(self) -> None:
        """
        Continuous monitoring loop for container security
        """
        self.logger.info(f"Monitoring for container security issues every {self.monitoring_interval} seconds")
        
        while not self.stop_monitoring.is_set():
            try:
                # Run security analysis
                results = self.analyze()
                
                # Log any security issues
                if results.get('is_anomalous', False):
                    stats = results.get('stats', {})
                    self.logger.warning(
                        f"Container security issues detected: "
                        f"{stats.get('privileged_count', 0)} privileged, "
                        f"{stats.get('no_limits_count', 0)} without limits, "
                        f"{stats.get('sensitive_mounts_count', 0)} sensitive mounts, "
                        f"{stats.get('risky_capabilities_count', 0)} risky capabilities, "
                        f"{stats.get('root_containers_count', 0)} as root, "
                        f"{stats.get('vulnerability_count', 0)} vulnerabilities, "
                        f"{stats.get('runtime_anomalies_count', 0)} runtime anomalies"
                    )
                
                # Sleep until next interval
                self.stop_monitoring.wait(self.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in container security monitoring loop: {e}")
                # Sleep a bit and continue
                time.sleep(5)