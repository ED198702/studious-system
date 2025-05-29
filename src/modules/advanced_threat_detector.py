#!/usr/bin/env python3
"""
Advanced Threat Detection Module for SharpEye
Uses machine learning and advanced analytics to detect sophisticated threats
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, Counter
import pickle
import hashlib
import re
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import networkx as nx
from scipy import stats

logger = logging.getLogger('sharpeye.advanced_threat_detector')


class ThreatPattern:
    """Represents a known threat pattern"""
    
    def __init__(self, pattern_id: str, name: str, category: str, 
                 indicators: List[Dict], confidence_threshold: float = 0.7):
        self.pattern_id = pattern_id
        self.name = name
        self.category = category
        self.indicators = indicators
        self.confidence_threshold = confidence_threshold
        self.matched_count = 0
        self.last_matched = None
    
    def match(self, data: Dict) -> Tuple[bool, float]:
        """
        Check if data matches this threat pattern
        
        Returns:
            Tuple of (matches, confidence_score)
        """
        matched_indicators = 0
        total_weight = 0
        matched_weight = 0
        
        for indicator in self.indicators:
            weight = indicator.get('weight', 1.0)
            total_weight += weight
            
            if self._check_indicator(indicator, data):
                matched_indicators += 1
                matched_weight += weight
        
        confidence = matched_weight / total_weight if total_weight > 0 else 0
        matches = confidence >= self.confidence_threshold
        
        if matches:
            self.matched_count += 1
            self.last_matched = datetime.now()
        
        return matches, confidence
    
    def _check_indicator(self, indicator: Dict, data: Dict) -> bool:
        """Check if a single indicator matches"""
        indicator_type = indicator.get('type')
        value = indicator.get('value')
        field = indicator.get('field')
        
        if not field or field not in data:
            return False
        
        data_value = data[field]
        
        if indicator_type == 'exact':
            return data_value == value
        elif indicator_type == 'contains':
            return value in str(data_value)
        elif indicator_type == 'regex':
            return bool(re.search(value, str(data_value)))
        elif indicator_type == 'range':
            min_val, max_val = value
            return min_val <= float(data_value) <= max_val
        elif indicator_type == 'in_list':
            return data_value in value
        
        return False


class AdvancedThreatDetector:
    """
    Advanced threat detection using ML and pattern recognition
    """
    
    def __init__(self, config: Dict = None):
        """Initialize the advanced threat detector"""
        self.config = config or {}
        self.logger = logger
        
        # Model paths
        self.model_dir = self.config.get('model_dir', '/var/lib/sharpeye/models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Initialize threat patterns
        self.threat_patterns = self._load_threat_patterns()
        
        # Initialize ML models
        self.anomaly_detector = None
        self.threat_classifier = None
        self.scaler = StandardScaler()
        
        # Feature extractors
        self.feature_extractors = {
            'process': self._extract_process_features,
            'network': self._extract_network_features,
            'file': self._extract_file_features,
            'user': self._extract_user_features
        }
        
        # Threat intelligence cache
        self.threat_cache = {}
        self.cache_ttl = timedelta(hours=24)
        
        # Attack graph for correlation
        self.attack_graph = nx.DiGraph()
        
        # Statistical baselines
        self.baselines = {}
        
        # Load or initialize models
        self._load_models()
        
        self.logger.info("Advanced threat detector initialized")
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive threat analysis
        
        Returns:
            Analysis results with detected threats
        """
        self.logger.info("Starting advanced threat analysis")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'threats': [],
            'risk_score': 0.0,
            'attack_chains': [],
            'predictions': {},
            'recommendations': []
        }
        
        try:
            # Collect system-wide data
            system_data = self._collect_system_data()
            
            # Pattern-based detection
            pattern_threats = self._detect_pattern_threats(system_data)
            results['threats'].extend(pattern_threats)
            
            # ML-based anomaly detection
            anomalies = self._detect_anomalies(system_data)
            results['threats'].extend(anomalies)
            
            # Threat classification
            if self.threat_classifier:
                classifications = self._classify_threats(system_data)
                results['predictions'] = classifications
            
            # Attack chain analysis
            attack_chains = self._analyze_attack_chains(results['threats'])
            results['attack_chains'] = attack_chains
            
            # Calculate overall risk score
            results['risk_score'] = self._calculate_risk_score(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
            # Update threat intelligence
            self._update_threat_intelligence(results)
            
        except Exception as e:
            self.logger.error(f"Error during threat analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def train_models(self, training_data: pd.DataFrame, labels: pd.Series = None):
        """
        Train ML models on historical data
        
        Args:
            training_data: DataFrame with features
            labels: Optional labels for supervised learning
        """
        self.logger.info("Training threat detection models")
        
        # Prepare features
        X = training_data.select_dtypes(include=[np.number])
        
        # Train anomaly detector (unsupervised)
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # Fit scaler and anomaly detector
        X_scaled = self.scaler.fit_transform(X)
        self.anomaly_detector.fit(X_scaled)
        
        # Train classifier if labels provided (supervised)
        if labels is not None:
            self.threat_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, labels, test_size=0.2, random_state=42
            )
            
            # Train classifier
            self.threat_classifier.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.threat_classifier.predict(X_test)
            report = classification_report(y_test, y_pred)
            self.logger.info(f"Classifier performance:\n{report}")
        
        # Save models
        self._save_models()
        
        self.logger.info("Model training completed")
    
    def _load_threat_patterns(self) -> List[ThreatPattern]:
        """Load predefined threat patterns"""
        patterns = []
        
        # APT behavior pattern
        apt_pattern = ThreatPattern(
            pattern_id="APT001",
            name="Advanced Persistent Threat",
            category="APT",
            indicators=[
                {
                    'field': 'process_name',
                    'type': 'regex',
                    'value': r'(powershell|cmd|wscript|cscript)',
                    'weight': 0.3
                },
                {
                    'field': 'network_behavior',
                    'type': 'contains',
                    'value': 'beacon',
                    'weight': 0.4
                },
                {
                    'field': 'persistence',
                    'type': 'exact',
                    'value': True,
                    'weight': 0.3
                }
            ]
        )
        patterns.append(apt_pattern)
        
        # Cryptominer pattern
        miner_pattern = ThreatPattern(
            pattern_id="MINER001",
            name="Cryptocurrency Miner",
            category="Cryptominer",
            indicators=[
                {
                    'field': 'cpu_usage',
                    'type': 'range',
                    'value': (80, 100),
                    'weight': 0.4
                },
                {
                    'field': 'process_name',
                    'type': 'regex',
                    'value': r'(xmr|monero|miner|nicehash)',
                    'weight': 0.3
                },
                {
                    'field': 'network_ports',
                    'type': 'in_list',
                    'value': [3333, 4444, 5555, 8333, 9050],
                    'weight': 0.3
                }
            ]
        )
        patterns.append(miner_pattern)
        
        # Ransomware pattern
        ransomware_pattern = ThreatPattern(
            pattern_id="RANSOM001",
            name="Ransomware Activity",
            category="Ransomware",
            indicators=[
                {
                    'field': 'file_operations',
                    'type': 'contains',
                    'value': 'mass_encryption',
                    'weight': 0.5
                },
                {
                    'field': 'file_extensions',
                    'type': 'regex',
                    'value': r'\.(locked|encrypted|enc|crypt)',
                    'weight': 0.3
                },
                {
                    'field': 'ransom_note',
                    'type': 'exact',
                    'value': True,
                    'weight': 0.2
                }
            ]
        )
        patterns.append(ransomware_pattern)
        
        # Data exfiltration pattern
        exfil_pattern = ThreatPattern(
            pattern_id="EXFIL001",
            name="Data Exfiltration",
            category="DataTheft",
            indicators=[
                {
                    'field': 'outbound_data_volume',
                    'type': 'range',
                    'value': (1000000000, float('inf')),  # > 1GB
                    'weight': 0.4
                },
                {
                    'field': 'destination_reputation',
                    'type': 'exact',
                    'value': 'malicious',
                    'weight': 0.4
                },
                {
                    'field': 'encryption_detected',
                    'type': 'exact',
                    'value': True,
                    'weight': 0.2
                }
            ]
        )
        patterns.append(exfil_pattern)
        
        return patterns
    
    def _collect_system_data(self) -> Dict[str, Any]:
        """Collect comprehensive system data for analysis"""
        import psutil
        
        data = {
            'timestamp': datetime.now(),
            'processes': [],
            'network_connections': [],
            'file_activities': [],
            'user_activities': [],
            'system_metrics': {}
        }
        
        # Collect process data
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.info
                proc_info['cmdline'] = proc.cmdline()
                proc_info['connections'] = len(proc.connections())
                data['processes'].append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Collect network data
        for conn in psutil.net_connections():
            if conn.raddr:
                conn_info = {
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                    'status': conn.status,
                    'pid': conn.pid
                }
                data['network_connections'].append(conn_info)
        
        # System metrics
        data['system_metrics'] = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
            'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
        }
        
        return data
    
    def _detect_pattern_threats(self, data: Dict) -> List[Dict]:
        """Detect threats using pattern matching"""
        threats = []
        
        # Prepare data for pattern matching
        pattern_data = self._prepare_pattern_data(data)
        
        # Check each pattern
        for pattern in self.threat_patterns:
            matches, confidence = pattern.match(pattern_data)
            
            if matches:
                threat = {
                    'type': 'pattern_match',
                    'pattern_id': pattern.pattern_id,
                    'name': pattern.name,
                    'category': pattern.category,
                    'confidence': confidence,
                    'severity': self._calculate_pattern_severity(pattern, confidence),
                    'details': {
                        'matched_count': pattern.matched_count,
                        'last_matched': pattern.last_matched.isoformat() if pattern.last_matched else None
                    },
                    'timestamp': datetime.now().isoformat()
                }
                threats.append(threat)
                
                self.logger.warning(f"Threat pattern detected: {pattern.name} (confidence: {confidence:.2f})")
        
        return threats
    
    def _detect_anomalies(self, data: Dict) -> List[Dict]:
        """Detect anomalies using ML models"""
        anomalies = []
        
        if not self.anomaly_detector:
            return anomalies
        
        # Extract features for each data type
        for data_type, extractor in self.feature_extractors.items():
            if data_type in data and data[data_type]:
                features_list = []
                entities = []
                
                # Extract features for each entity
                for entity in data.get(data_type, []):
                    features = extractor(entity)
                    if features:
                        features_list.append(list(features.values()))
                        entities.append(entity)
                
                if features_list:
                    # Convert to numpy array
                    X = np.array(features_list)
                    
                    # Scale features
                    try:
                        X_scaled = self.scaler.transform(X)
                    except:
                        # Fit scaler if not fitted
                        X_scaled = self.scaler.fit_transform(X)
                    
                    # Predict anomalies
                    predictions = self.anomaly_detector.predict(X_scaled)
                    scores = self.anomaly_detector.score_samples(X_scaled)
                    
                    # Process anomalies
                    for i, (pred, score) in enumerate(zip(predictions, scores)):
                        if pred == -1:  # Anomaly
                            anomaly = {
                                'type': 'ml_anomaly',
                                'category': data_type,
                                'confidence': abs(score),
                                'severity': self._calculate_anomaly_severity(score),
                                'entity': entities[i],
                                'features': dict(zip(features.keys(), features_list[i])),
                                'timestamp': datetime.now().isoformat()
                            }
                            anomalies.append(anomaly)
                            
                            self.logger.warning(f"ML anomaly detected in {data_type}: score={score:.3f}")
        
        return anomalies
    
    def _classify_threats(self, data: Dict) -> Dict[str, Any]:
        """Classify threats using supervised ML"""
        if not self.threat_classifier:
            return {}
        
        classifications = {}
        
        # Extract global features
        features = self._extract_global_features(data)
        
        if features:
            X = np.array([list(features.values())])
            
            # Scale features
            try:
                X_scaled = self.scaler.transform(X)
            except:
                return {}
            
            # Predict threat class and probability
            threat_class = self.threat_classifier.predict(X_scaled)[0]
            threat_proba = self.threat_classifier.predict_proba(X_scaled)[0]
            
            classifications = {
                'predicted_class': threat_class,
                'class_probabilities': dict(zip(
                    self.threat_classifier.classes_,
                    threat_proba
                )),
                'confidence': float(np.max(threat_proba))
            }
        
        return classifications
    
    def _analyze_attack_chains(self, threats: List[Dict]) -> List[Dict]:
        """Analyze potential attack chains from detected threats"""
        attack_chains = []
        
        # Build threat graph
        self.attack_graph.clear()
        
        # Add threats as nodes
        for i, threat in enumerate(threats):
            self.attack_graph.add_node(i, **threat)
        
        # Add edges based on temporal and logical relationships
        for i in range(len(threats)):
            for j in range(i + 1, len(threats)):
                if self._threats_related(threats[i], threats[j]):
                    self.attack_graph.add_edge(i, j)
        
        # Find attack chains (paths in graph)
        for component in nx.weakly_connected_components(self.attack_graph):
            if len(component) > 1:
                chain_nodes = sorted(component)
                chain = {
                    'chain_id': hashlib.md5(str(chain_nodes).encode()).hexdigest()[:8],
                    'length': len(chain_nodes),
                    'threats': [threats[i] for i in chain_nodes],
                    'tactics': self._identify_tactics(chain_nodes, threats),
                    'likelihood': self._calculate_chain_likelihood(chain_nodes, threats),
                    'impact': self._calculate_chain_impact(chain_nodes, threats)
                }
                attack_chains.append(chain)
        
        return attack_chains
    
    def _calculate_risk_score(self, results: Dict) -> float:
        """Calculate overall risk score"""
        risk_score = 0.0
        
        # Factor in individual threats
        for threat in results.get('threats', []):
            confidence = threat.get('confidence', 0.5)
            severity_map = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
            severity = severity_map.get(threat.get('severity', 'medium'), 0.5)
            risk_score += confidence * severity * 0.3
        
        # Factor in attack chains
        for chain in results.get('attack_chains', []):
            chain_risk = chain.get('likelihood', 0.5) * chain.get('impact', 0.5)
            risk_score += chain_risk * 0.5
        
        # Factor in ML predictions
        predictions = results.get('predictions', {})
        if predictions:
            confidence = predictions.get('confidence', 0)
            if predictions.get('predicted_class') in ['malicious', 'suspicious']:
                risk_score += confidence * 0.2
        
        # Normalize to 0-1 range
        risk_score = min(1.0, risk_score)
        
        return round(risk_score, 3)
    
    def _generate_recommendations(self, results: Dict) -> List[Dict]:
        """Generate actionable recommendations based on threats"""
        recommendations = []
        
        risk_score = results.get('risk_score', 0)
        
        # High-level recommendations based on risk
        if risk_score > 0.8:
            recommendations.append({
                'priority': 'critical',
                'action': 'isolate_system',
                'description': 'Immediately isolate affected systems from network',
                'reason': 'Critical risk level detected'
            })
        
        # Threat-specific recommendations
        threat_categories = defaultdict(int)
        for threat in results.get('threats', []):
            threat_categories[threat.get('category', 'unknown')] += 1
        
        for category, count in threat_categories.items():
            if category == 'APT':
                recommendations.append({
                    'priority': 'high',
                    'action': 'forensic_analysis',
                    'description': 'Conduct deep forensic analysis of affected systems',
                    'reason': f'Advanced persistent threat indicators detected ({count} indicators)'
                })
            elif category == 'Cryptominer':
                recommendations.append({
                    'priority': 'medium',
                    'action': 'kill_processes',
                    'description': 'Terminate suspected mining processes and block mining pools',
                    'reason': f'Cryptocurrency mining activity detected ({count} instances)'
                })
            elif category == 'Ransomware':
                recommendations.append({
                    'priority': 'critical',
                    'action': 'backup_restore',
                    'description': 'Immediately backup critical data and prepare for restoration',
                    'reason': f'Ransomware indicators detected ({count} indicators)'
                })
        
        # Attack chain recommendations
        for chain in results.get('attack_chains', []):
            if chain.get('length', 0) > 3:
                recommendations.append({
                    'priority': 'high',
                    'action': 'incident_response',
                    'description': 'Activate incident response team for coordinated threat response',
                    'reason': f'Complex attack chain detected with {chain["length"]} stages'
                })
        
        return recommendations
    
    def _prepare_pattern_data(self, data: Dict) -> Dict:
        """Prepare data for pattern matching"""
        pattern_data = {}
        
        # Process-related indicators
        suspicious_processes = sum(1 for p in data.get('processes', []) 
                                 if p.get('name', '').lower() in ['powershell.exe', 'cmd.exe'])
        pattern_data['process_name'] = 'powershell' if suspicious_processes > 0 else ''
        
        # Network-related indicators
        connections = data.get('network_connections', [])
        beacon_like = any(self._is_beacon_behavior(connections))
        pattern_data['network_behavior'] = 'beacon' if beacon_like else 'normal'
        
        # Calculate aggregate metrics
        cpu_usage = data.get('system_metrics', {}).get('cpu_percent', 0)
        pattern_data['cpu_usage'] = cpu_usage
        
        # File activity indicators
        pattern_data['file_operations'] = 'normal'
        pattern_data['file_extensions'] = ''
        
        # Check for persistence mechanisms
        pattern_data['persistence'] = False
        
        return pattern_data
    
    def _is_beacon_behavior(self, connections: List[Dict]) -> bool:
        """Check if network connections exhibit beacon-like behavior"""
        if len(connections) < 5:
            return False
        
        # Group connections by remote address
        conn_times = defaultdict(list)
        for conn in connections:
            remote = conn.get('remote_addr', '')
            if remote:
                conn_times[remote].append(datetime.now())
        
        # Check for regular intervals
        for remote, times in conn_times.items():
            if len(times) >= 3:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                interval_seconds = [i.total_seconds() for i in intervals]
                
                # Check if intervals are regular (low standard deviation)
                if interval_seconds:
                    std_dev = np.std(interval_seconds)
                    mean_interval = np.mean(interval_seconds)
                    if std_dev < mean_interval * 0.2:  # Less than 20% variation
                        return True
        
        return False
    
    def _extract_process_features(self, process: Dict) -> Dict[str, float]:
        """Extract features from process data"""
        features = {}
        
        # Basic metrics
        features['cpu_percent'] = process.get('cpu_percent', 0)
        features['memory_percent'] = process.get('memory_percent', 0)
        features['num_connections'] = process.get('connections', 0)
        
        # Process name entropy (randomness)
        name = process.get('name', '')
        features['name_entropy'] = self._calculate_entropy(name)
        
        # Command line length
        cmdline = ' '.join(process.get('cmdline', []))
        features['cmdline_length'] = len(cmdline)
        
        # Suspicious indicators
        features['is_hidden'] = 1 if name.startswith('.') else 0
        features['is_system_path'] = 1 if '/system' in cmdline.lower() else 0
        
        return features
    
    def _extract_network_features(self, connection: Dict) -> Dict[str, float]:
        """Extract features from network connection data"""
        features = {}
        
        # Parse addresses
        local_addr = connection.get('local_addr', ':')
        remote_addr = connection.get('remote_addr', ':')
        
        local_port = int(local_addr.split(':')[-1]) if ':' in local_addr else 0
        remote_port = int(remote_addr.split(':')[-1]) if ':' in remote_addr else 0
        
        # Port-based features
        features['local_port'] = local_port
        features['remote_port'] = remote_port
        features['is_common_port'] = 1 if remote_port in [80, 443, 22, 21, 25] else 0
        features['is_high_port'] = 1 if remote_port > 10000 else 0
        
        # Connection state
        state = connection.get('status', '')
        features['is_established'] = 1 if state == 'ESTABLISHED' else 0
        features['is_listening'] = 1 if state == 'LISTEN' else 0
        
        return features
    
    def _extract_file_features(self, file_activity: Dict) -> Dict[str, float]:
        """Extract features from file activity data"""
        features = {}
        
        # File path analysis
        path = file_activity.get('path', '')
        features['path_depth'] = path.count('/')
        features['is_hidden'] = 1 if '/' in path and path.split('/')[-1].startswith('.') else 0
        features['is_system'] = 1 if path.startswith('/etc') or path.startswith('/sys') else 0
        
        # Operation type
        operation = file_activity.get('operation', '')
        features['is_write'] = 1 if 'write' in operation.lower() else 0
        features['is_delete'] = 1 if 'delete' in operation.lower() else 0
        
        return features
    
    def _extract_user_features(self, user_activity: Dict) -> Dict[str, float]:
        """Extract features from user activity data"""
        features = {}
        
        # Login characteristics
        features['is_remote'] = 1 if user_activity.get('is_remote', False) else 0
        features['login_hour'] = datetime.now().hour
        features['is_suspicious_hour'] = 1 if features['login_hour'] in [0, 1, 2, 3, 4, 5] else 0
        
        # Session duration
        login_time = user_activity.get('login_time', 0)
        if login_time:
            duration = (datetime.now() - datetime.fromtimestamp(login_time)).total_seconds()
            features['session_duration'] = duration
        else:
            features['session_duration'] = 0
        
        return features
    
    def _extract_global_features(self, data: Dict) -> Dict[str, float]:
        """Extract system-wide features for classification"""
        features = {}
        
        # System metrics
        metrics = data.get('system_metrics', {})
        features['cpu_percent'] = metrics.get('cpu_percent', 0)
        features['memory_percent'] = metrics.get('memory_percent', 0)
        
        # Process statistics
        processes = data.get('processes', [])
        features['num_processes'] = len(processes)
        features['suspicious_processes'] = sum(1 for p in processes 
                                             if p.get('name', '').lower() in ['nc', 'ncat', 'socat'])
        
        # Network statistics
        connections = data.get('network_connections', [])
        features['num_connections'] = len(connections)
        features['external_connections'] = sum(1 for c in connections 
                                             if not c.get('remote_addr', '').startswith('127.'))
        
        # Calculate entropy of various system aspects
        process_names = [p.get('name', '') for p in processes]
        features['process_diversity'] = len(set(process_names)) / len(process_names) if process_names else 0
        
        return features
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        # Calculate frequency of each character
        freq = Counter(string)
        probs = [freq[c] / len(string) for c in freq]
        
        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in probs if p > 0)
        
        return entropy
    
    def _calculate_pattern_severity(self, pattern: ThreatPattern, confidence: float) -> str:
        """Calculate severity based on pattern and confidence"""
        base_severity = {
            'APT': 0.9,
            'Ransomware': 1.0,
            'Cryptominer': 0.6,
            'DataTheft': 0.8
        }
        
        severity_score = base_severity.get(pattern.category, 0.5) * confidence
        
        if severity_score >= 0.8:
            return 'critical'
        elif severity_score >= 0.6:
            return 'high'
        elif severity_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_anomaly_severity(self, anomaly_score: float) -> str:
        """Calculate severity based on anomaly score"""
        abs_score = abs(anomaly_score)
        
        if abs_score >= 0.8:
            return 'high'
        elif abs_score >= 0.6:
            return 'medium'
        else:
            return 'low'
    
    def _threats_related(self, threat1: Dict, threat2: Dict) -> bool:
        """Check if two threats are related"""
        # Temporal relationship (within 5 minutes)
        time1 = datetime.fromisoformat(threat1.get('timestamp', ''))
        time2 = datetime.fromisoformat(threat2.get('timestamp', ''))
        time_diff = abs((time2 - time1).total_seconds())
        
        if time_diff > 300:  # 5 minutes
            return False
        
        # Category relationship
        cat1 = threat1.get('category', '')
        cat2 = threat2.get('category', '')
        
        related_categories = {
            'APT': ['DataTheft', 'Persistence'],
            'Ransomware': ['FileEncryption', 'DataDestruction'],
            'Cryptominer': ['ResourceAbuse', 'Backdoor']
        }
        
        if cat1 in related_categories and cat2 in related_categories.get(cat1, []):
            return True
        
        # Entity relationship (same process, file, etc.)
        entity1 = threat1.get('entity', {})
        entity2 = threat2.get('entity', {})
        
        if entity1.get('pid') and entity1.get('pid') == entity2.get('pid'):
            return True
        
        return False
    
    def _identify_tactics(self, chain_nodes: List[int], threats: List[Dict]) -> List[str]:
        """Identify MITRE ATT&CK tactics in attack chain"""
        tactics = set()
        
        tactic_mapping = {
            'APT': 'Persistence',
            'Cryptominer': 'Resource Development',
            'Ransomware': 'Impact',
            'DataTheft': 'Exfiltration',
            'process': 'Execution',
            'network': 'Command and Control',
            'file': 'Defense Evasion'
        }
        
        for node in chain_nodes:
            threat = threats[node]
            category = threat.get('category', '')
            if category in tactic_mapping:
                tactics.add(tactic_mapping[category])
        
        return sorted(list(tactics))
    
    def _calculate_chain_likelihood(self, chain_nodes: List[int], threats: List[Dict]) -> float:
        """Calculate likelihood of attack chain"""
        if not chain_nodes:
            return 0.0
        
        # Average confidence of threats in chain
        confidences = [threats[i].get('confidence', 0.5) for i in chain_nodes]
        avg_confidence = np.mean(confidences)
        
        # Factor in chain length (longer chains less likely)
        length_factor = 1.0 / (1 + len(chain_nodes) * 0.1)
        
        return min(1.0, avg_confidence * length_factor)
    
    def _calculate_chain_impact(self, chain_nodes: List[int], threats: List[Dict]) -> float:
        """Calculate potential impact of attack chain"""
        if not chain_nodes:
            return 0.0
        
        impact_scores = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25
        }
        
        # Maximum severity in chain
        severities = [threats[i].get('severity', 'medium') for i in chain_nodes]
        max_impact = max(impact_scores.get(s, 0.5) for s in severities)
        
        # Factor in chain length (longer chains potentially more damaging)
        length_factor = min(1.0, len(chain_nodes) * 0.2)
        
        return min(1.0, max_impact + length_factor)
    
    def _update_threat_intelligence(self, results: Dict):
        """Update internal threat intelligence based on findings"""
        # Update threat pattern match counts
        for threat in results.get('threats', []):
            if threat.get('type') == 'pattern_match':
                pattern_id = threat.get('pattern_id')
                # Update pattern statistics
                
        # Update baselines if no threats
        if not results.get('threats') and results.get('risk_score', 0) < 0.2:
            # System is clean, update baselines
            pass
    
    def _save_models(self):
        """Save trained models to disk"""
        if self.anomaly_detector:
            joblib.dump(self.anomaly_detector, 
                       os.path.join(self.model_dir, 'anomaly_detector.pkl'))
        
        if self.threat_classifier:
            joblib.dump(self.threat_classifier,
                       os.path.join(self.model_dir, 'threat_classifier.pkl'))
        
        if self.scaler:
            joblib.dump(self.scaler,
                       os.path.join(self.model_dir, 'feature_scaler.pkl'))
        
        self.logger.info("Models saved successfully")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            anomaly_path = os.path.join(self.model_dir, 'anomaly_detector.pkl')
            if os.path.exists(anomaly_path):
                self.anomaly_detector = joblib.load(anomaly_path)
                self.logger.info("Loaded anomaly detector model")
            
            classifier_path = os.path.join(self.model_dir, 'threat_classifier.pkl')
            if os.path.exists(classifier_path):
                self.threat_classifier = joblib.load(classifier_path)
                self.logger.info("Loaded threat classifier model")
            
            scaler_path = os.path.join(self.model_dir, 'feature_scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                self.logger.info("Loaded feature scaler")
                
        except Exception as e:
            self.logger.warning(f"Could not load models: {str(e)}")