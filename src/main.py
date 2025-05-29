#!/usr/bin/env python3
"""
SharpEye - Linux Intrusion Detection System
Main entry point for the application.
"""

import os
import sys
import argparse
import logging
import yaml
from datetime import datetime
from typing import Dict

# Import modules
from modules.system_resources import ResourcePatternAnalyzer
from modules.user_accounts import UserAccountAnalyzer
from modules.processes import ProcessRelationshipMapper
from modules.network import NetworkAnalyzer
from modules.file_integrity import FileIntegrityMonitor
from modules.log_analysis import LogAnalysisEngine
from modules.kernel_modules import KernelModuleAnalyzer
from modules.library_inspection import LibraryInspector
from modules.privilege_escalation import PrivilegeEscalationDetector
from modules.ssh_analyzer import SSHAnalyzer
from modules.cryptominer import CryptominerDetectionModule
from modules.rootkit_detector import RootkitDetector
from modules.scheduled_tasks import ScheduledTasksAnalyzer
from modules.behavior_monitor import BehaviorMonitor
from modules.container_security import ContainerSecurityModule
from modules.advanced_threat_detector import AdvancedThreatDetector
from utils.reporter import Reporter
from utils.behavior_analysis import BehaviorAnalyzer
from utils.threat_intelligence import ThreatIntelligenceManager
from utils.alerting import get_alert_manager, AlertPriority

# Setup logging
def setup_logging(log_level):
    """Configure logging settings"""
    log_levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    level = log_levels.get(log_level.lower(), logging.INFO)
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Set up logging to file and console
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f"logs/sharpeye_{timestamp}.log"
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger('sharpeye')

def load_config(config_path):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as config_file:
            return yaml.safe_load(config_file)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        return {}

def enhance_with_threat_intelligence(results, threat_intel, module_name):
    """
    Enhance analysis results with threat intelligence data
    
    Args:
        results: Module analysis results
        threat_intel: ThreatIntelligenceManager instance
        module_name: Name of the module
        
    Returns:
        Enhanced results with threat intelligence data
    """
    if not threat_intel or not results:
        return results
    
    enhanced_results = results.copy()
    threat_findings = []
    
    # Network module - check IPs and domains
    if module_name == 'network':
        connections = results.get('connections', [])
        for conn in connections:
            remote_ip = conn.get('remote_ip')
            if remote_ip and remote_ip not in ['127.0.0.1', '0.0.0.0']:
                ioc_results = threat_intel.check_ioc(remote_ip)
                if ioc_results:
                    for ioc in ioc_results:
                        if ioc.malicious:
                            threat_findings.append({
                                'type': 'malicious_ip',
                                'value': remote_ip,
                                'source': ioc.source,
                                'confidence': ioc.confidence,
                                'description': ioc.description,
                                'connection': conn
                            })
    
    # Process module - check process hashes and names
    elif module_name == 'processes':
        processes = results.get('suspicious_processes', [])
        for proc in processes:
            # Check process executable hash if available
            exe_hash = proc.get('exe_hash')
            if exe_hash:
                ioc_results = threat_intel.check_ioc(exe_hash)
                if ioc_results:
                    for ioc in ioc_results:
                        if ioc.malicious:
                            threat_findings.append({
                                'type': 'malicious_hash',
                                'value': exe_hash,
                                'source': ioc.source,
                                'confidence': ioc.confidence,
                                'description': ioc.description,
                                'process': proc
                            })
    
    # File integrity module - check file hashes
    elif module_name == 'file_integrity':
        modified_files = results.get('modified_files', [])
        for file_info in modified_files:
            file_hash = file_info.get('current_hash')
            if file_hash:
                ioc_results = threat_intel.check_ioc(file_hash)
                if ioc_results:
                    for ioc in ioc_results:
                        if ioc.malicious:
                            threat_findings.append({
                                'type': 'malicious_file',
                                'value': file_hash,
                                'source': ioc.source,
                                'confidence': ioc.confidence,
                                'description': ioc.description,
                                'file': file_info
                            })
    
    # Add threat intelligence findings to results
    if threat_findings:
        enhanced_results['threat_intelligence'] = {
            'findings': threat_findings,
            'total_threats': len(threat_findings),
            'sources': list(set(f['source'] for f in threat_findings))
        }
        enhanced_results['is_anomalous'] = True
    
    return enhanced_results


def determine_severity(results: Dict) -> str:
    """
    Determine alert severity based on analysis results
    
    Args:
        results: Module analysis results
        
    Returns:
        Alert priority level
    """
    # Check for critical indicators
    if results.get('critical_findings', 0) > 0:
        return AlertPriority.CRITICAL
    
    # Check threat intelligence results
    threat_intel = results.get('threat_intelligence', {})
    if threat_intel.get('total_threats', 0) > 0:
        return AlertPriority.HIGH
    
    # Check anomaly scores
    anomaly_count = len(results.get('anomalies', []))
    if anomaly_count > 10:
        return AlertPriority.HIGH
    elif anomaly_count > 5:
        return AlertPriority.MEDIUM
    elif anomaly_count > 0:
        return AlertPriority.LOW
    
    # Check specific module indicators
    if 'rootkit' in results:
        return AlertPriority.CRITICAL
    elif 'ransomware' in str(results).lower():
        return AlertPriority.CRITICAL
    elif 'cryptominer' in str(results).lower():
        return AlertPriority.HIGH
    
    return AlertPriority.MEDIUM


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SharpEye - Linux Intrusion Detection System'
    )
    
    parser.add_argument(
        '--config', 
        default='/etc/sharpeye/config.yaml',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        default='info',
        help='Set logging level'
    )
    
    parser.add_argument(
        '--output-dir',
        default='./reports',
        help='Directory to store reports'
    )
    
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--full-scan',
        action='store_true',
        help='Run all detection modules'
    )
    
    scan_group.add_argument(
        '--module',
        choices=[
            'system', 'users', 'processes', 'network', 'file_integrity',
            'log_analysis', 'kernel_modules', 'library_inspection', 'privilege_escalation',
            'ssh', 'cryptominer', 'rootkit', 'scheduled_tasks', 'behavior', 'container_security',
            'advanced_threats'
        ],
        help='Run a specific detection module'
    )
    
    baseline_group = parser.add_argument_group('Baseline Options')
    baseline_group.add_argument(
        '--establish-baseline',
        action='store_true',
        help='Establish baseline for future comparison'
    )
    
    baseline_group.add_argument(
        '--compare-baseline',
        action='store_true',
        help='Compare against previously established baseline'
    )
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--format',
        choices=['text', 'json', 'html', 'pdf'],
        default='text',
        help='Report output format'
    )
    
    output_group.add_argument(
        '--email',
        help='Email address to send reports to'
    )
    
    # Web dashboard options
    web_group = parser.add_argument_group('Web Dashboard Options')
    web_group.add_argument(
        '--web',
        action='store_true',
        help='Start web dashboard interface'
    )
    web_group.add_argument(
        '--web-host',
        default='0.0.0.0',
        help='Web dashboard host address'
    )
    web_group.add_argument(
        '--web-port',
        type=int,
        default=5000,
        help='Web dashboard port'
    )
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    logger.info("Starting SharpEye Intrusion Detection System")
    
    # Load configuration
    config = load_config(args.config)
    
    # Initialize alert manager
    alert_manager = get_alert_manager(config.get('alerting', {}))
    
    # Initialize analyzers (moved up for dashboard access)
    analyzers = {
        'system': ResourcePatternAnalyzer(config.get('system_resources', {})),
        'users': UserAccountAnalyzer(config.get('user_accounts', {})),
        'processes': ProcessRelationshipMapper(config.get('processes', {})),
        'network': NetworkAnalyzer(config.get('network', {})),
        'file_integrity': FileIntegrityMonitor(config.get('file_integrity', {})),
        'log_analysis': LogAnalysisEngine(config.get('log_analysis', {})),
        'kernel_modules': KernelModuleAnalyzer(config.get('kernel_modules', {})),
        'library_inspection': LibraryInspector(config.get('library_inspection', {})),
        'privilege_escalation': PrivilegeEscalationDetector(config.get('privilege_escalation', {})),
        'ssh': SSHAnalyzer(config.get('ssh', {})),
        'cryptominer': CryptominerDetectionModule(config.get('cryptominer', {})),
        'rootkit': RootkitDetector(config.get('rootkit', {})),
        'scheduled_tasks': ScheduledTasksAnalyzer(config.get('scheduled_tasks', {})),
        'behavior': BehaviorMonitor(config.get('behavior_monitor', {})),
        'container_security': ContainerSecurityModule(config.get('container_security', {})),
        'advanced_threats': AdvancedThreatDetector(config.get('advanced_threats', {}))
    }
    
    # Start web dashboard if requested
    if args.web:
        from web.dashboard import create_dashboard_app
        dashboard = create_dashboard_app(config.get('dashboard', {}))
        
        # Set up modules for dashboard
        if config.get('behavior_monitor', {}).get('enabled', False):
            behavior_monitor = analyzers.get('behavior')
            if behavior_monitor:
                dashboard.set_behavior_monitor(behavior_monitor)
        
        if config.get('advanced_threats', {}).get('enabled', False):
            threat_detector = analyzers.get('advanced_threats')
            if threat_detector:
                dashboard.set_threat_detector(threat_detector)
        
        # Run dashboard in background thread
        import threading
        dashboard_thread = threading.Thread(
            target=dashboard.run,
            kwargs={'host': args.web_host, 'port': args.web_port},
            daemon=True
        )
        dashboard_thread.start()
        logger.info(f"Web dashboard started on http://{args.web_host}:{args.web_port}")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Initialize reporter
    reporter = Reporter(args.output_dir, args.format)
    
    # Initialize threat intelligence if configured
    threat_intel = None
    if config.get('threat_intelligence', {}).get('enabled', False):
        threat_intel = ThreatIntelligenceManager(config.get('threat_intelligence', {}))
        logger.info("Threat intelligence integration enabled")
        
        # Test connections to threat intelligence providers
        connection_status = threat_intel.test_connections()
        for provider, status in connection_status.items():
            if status:
                logger.info(f"Successfully connected to {provider}")
            else:
                logger.warning(f"Failed to connect to {provider}")
    
    # Run in baseline mode
    if args.establish_baseline:
        logger.info("Establishing system baseline")
        # Run each analyzer in baseline mode
        for name, analyzer in analyzers.items():
            if hasattr(analyzer, 'establish_baseline'):
                logger.info(f"Establishing baseline for {name} module")
                analyzer.establish_baseline()
        logger.info("Baseline establishment complete")
        return
    
    # Run in comparison mode
    if args.compare_baseline:
        logger.info("Comparing against baseline")
        for name, analyzer in analyzers.items():
            if hasattr(analyzer, 'compare_baseline'):
                logger.info(f"Comparing baseline for {name} module")
                results = analyzer.compare_baseline()
                reporter.add_section(name, results)
        reporter.generate_report()
        return
    
    # Run specific module
    if args.module:
        logger.info(f"Running {args.module} module")
        analyzer = analyzers.get(args.module)
        if analyzer:
            results = analyzer.analyze()
            reporter.add_section(args.module, results)
            reporter.generate_report()
        else:
            logger.error(f"Module {args.module} not found")
        return
    
    # Run full scan
    if args.full_scan or not (args.establish_baseline or args.compare_baseline or args.module):
        logger.info("Running full system scan")
        for name, analyzer in analyzers.items():
            logger.info(f"Running {name} module")
            results = analyzer.analyze()
            
            # Enhance results with threat intelligence if available
            if threat_intel and name in ['network', 'file_integrity', 'processes']:
                results = enhance_with_threat_intelligence(results, threat_intel, name)
            
            # Generate alerts for anomalies
            if results.get('is_anomalous', False):
                severity = determine_severity(results)
                alert = alert_manager.create_alert(
                    title=f"Anomaly detected in {name} module",
                    description=f"Security anomaly detected during {name} analysis",
                    priority=severity,
                    source=name,
                    category='anomaly',
                    data=results
                )
                alert_manager.send_alert(alert)
            
            reporter.add_section(name, results)
        
        # Generate and possibly email the report
        report_path = reporter.generate_report()
        
        if args.email and report_path:
            # TODO: Add email functionality
            logger.info(f"Report would be emailed to {args.email}")
    
    logger.info("SharpEye scan completed")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: SharpEye requires root privileges to function properly.")
        print("Please run with sudo or as root.")
        sys.exit(1)
    
    main()