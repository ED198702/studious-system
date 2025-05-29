# Machine Learning Analysis in SharpEye

SharpEye incorporates advanced machine learning techniques to enhance its anomaly detection capabilities. This document provides an overview of the ML-based analysis features, including system resource monitoring and the new comprehensive behavior anomaly detection system.

## Behavior Anomaly Detection

The latest SharpEye update introduces a powerful behavior anomaly detection framework that provides comprehensive monitoring of system behaviors to identify potential security threats. This framework represents a significant enhancement to SharpEye's security capabilities.

### Overview

The behavior anomaly detection system monitors and analyzes various aspects of system behavior:

1. **Process Behavior** - Monitors process resource usage, relationships, execution patterns, and lifecycle
2. **User Behavior** - Tracks user activities, login patterns, command usage, and privilege changes
3. **System Resource Behavior** - Monitors system-wide resource usage patterns and anomalies
4. **File System Behavior** - Detects unusual file operations, access patterns, and modifications
5. **Network Behavior** - Identifies unusual connection patterns, data transfers, and communications

Each behavioral domain is analyzed using machine learning techniques to establish normal behavior baselines and detect deviations that may indicate security threats.

### Key Components

#### 1. Behavior Analyzer

The core `BehaviorAnalyzer` class implements:

- Feature extraction from raw system data
- Baseline establishment and maintenance
- Anomaly detection using Isolation Forest algorithm
- Severity assessment and reporting

#### 2. Behavior Monitor

The `BehaviorMonitor` service provides:

- Real-time monitoring across all behavior domains
- Coordination between specialized monitoring components
- Periodic reporting and alerting
- Baseline management

#### 3. Specialized Analyzers

Dedicated analyzers for each behavior domain:

- `ProcessBehaviorAnalyzer` - Process-specific anomaly detection
- `UserBehaviorAnalyzer` - User activity analysis
- `SystemResourceAnalyzer` - System-wide resource monitoring
- `FileSystemAnalyzer` - File operation monitoring
- `NetworkBehaviorAnalyzer` - Network communication analysis

### Implementation Highlights

- **Isolation Forest Algorithm** - Efficient unsupervised learning for anomaly detection
- **Contextual Anomaly Detection** - Considers behavioral context when identifying anomalies
- **Multi-dimensional Analysis** - Examines multiple data points simultaneously
- **Temporal Pattern Recognition** - Identifies unusual patterns developing over time
- **Cross-domain Correlation** - Connects anomalies across different behavior domains

### Usage

The behavior anomaly detection can be run as a standalone module:

```bash
sudo sharpeye --module behavior
```

Or enabled as a continuous background service in the configuration:

```yaml
behavior_monitor:
  continuous_monitoring: true
```

## System Resource Pattern Analysis

The system resource module (`SystemResourceAnalyzer`) has been enhanced with machine learning capabilities for detecting anomalous resource usage patterns that might indicate compromise or security threats.

### Overview

Traditional threshold-based anomaly detection is useful but has limitations:
- Fixed thresholds may miss subtle anomalies
- Cannot detect correlations between different resources
- Unable to recognize patterns that develop over time
- Cannot learn from system's normal behavior

The machine learning enhancement addresses these limitations by:
- Analyzing resource usage patterns over time
- Detecting anomalies based on deviations from expected behavior
- Identifying correlations between different resource types
- Recognizing suspicious trends and patterns that evolve gradually

### Implemented Techniques

The `ResourcePatternAnalyzer` class implements several machine learning and statistical analysis approaches:

1. **Unsupervised Anomaly Detection** - Using Isolation Forest algorithm to identify anomalous resource usage patterns
2. **Time Series Analysis** - Tracking resource metrics over time to detect unusual changes
3. **Correlation Analysis** - Detecting suspicious correlations between different resource types
4. **Trend Analysis** - Identifying concerning trends using linear regression

### Key Features

#### 1. Historical Data Analysis

The analyzer maintains a history of resource metrics, allowing it to establish a baseline of normal behavior:
- Configurable history length (default: 24 data points)
- Automatic feature extraction from CPU, memory, and disk data
- Rolling window analysis for continuous monitoring

#### 2. Machine Learning Models

Three separate ML models are used to detect anomalies in different resource types:
- CPU usage pattern anomaly detection
- Memory usage pattern anomaly detection
- Disk usage pattern anomaly detection

The models are implemented using scikit-learn's Isolation Forest algorithm, which:
- Does not require labeled training data
- Works well with high-dimensional data
- Is efficient for real-time anomaly detection
- Can detect outliers in the feature space

#### 3. Cross-Resource Correlation Analysis

Beyond individual resource anomalies, the analyzer detects suspicious correlations between resources:
- CPU and memory usage patterns
- Disk I/O and CPU patterns
- System and user CPU time ratios
- Unusual resource convergence patterns

Common attack patterns detected include:
- High disk I/O without corresponding CPU usage (potential data exfiltration)
- Perfectly correlated resource usage (potential coordinated attack)
- High CPU with decreasing available memory (resource exhaustion attack)

#### 4. Statistical Pattern Detection

Even without trained models, the analyzer uses statistical methods to identify suspicious patterns:
- Sudden resource usage spikes
- Sustained high load
- Unusual system-to-user CPU ratio
- Memory fragmentation increases
- Suspicious process behavior

#### 5. Self-Training Capability

The analyzer can train its own models based on observed system behavior:
- Automatically trains models after collecting sufficient history
- Adapts to the specific system's baseline behavior
- No need for pre-labeled training data

### Implementation Details

#### Feature Extraction

For effective ML analysis, raw resource data is transformed into feature vectors:

**CPU Features:**
- Total CPU usage percentage
- Count of high-CPU processes
- Count of anomalous processes
- Count of hidden processes
- System load average
- I/O wait percentage
- System CPU percentage
- User CPU percentage

**Memory Features:**
- Memory usage percentage
- Swap usage percentage
- Count of high-memory processes
- Count of anomalous processes
- Cached-to-free memory ratio
- Anonymous pages count
- Slab memory usage
- Memory fragmentation index

**Disk Features:**
- Average filesystem usage percentage
- Count of anomalous filesystems
- Count of suspicious directories
- Count of hidden files
- Count of large files
- Suspicious growth indicator
- Count of permission issues
- Count of modified configuration files

#### Analysis Workflow

The machine learning analysis follows this workflow:

1. During system initialization, ML models are loaded if available
2. With each resource analysis, metrics are extracted and added to history
3. If sufficient history exists (≥3 samples), pattern analysis is performed
4. Anomalies are detected using both ML and statistical methods
5. After collecting sufficient samples (≥10), models are trained if not already available

#### Integration with Traditional Analysis

ML-based analysis complements, rather than replaces, traditional threshold-based detection:
- Traditional analysis catches immediate, obvious anomalies
- ML analysis catches subtle, evolving, or correlated anomalies
- Results from both approaches are combined in the final report

### Configuration

The ML-based analysis can be configured in the SharpEye configuration file:

```yaml
system_resources:
  # Traditional thresholds
  cpu_threshold: 90
  memory_threshold: 90
  disk_threshold: 90
  
  # ML configuration
  ml_config:
    enable: true               # Enable/disable ML analysis
    history_length: 24         # Number of samples to keep in history
    detection_threshold: 0.7   # Anomaly detection threshold (0-1)
    models_dir: /var/lib/sharpeye/models  # Directory for saving/loading models
```

### Sample Output

When ML-based anomalies are detected, they are included in the analysis results:

```json
{
  "cpu": {
    "is_anomalous": true,
    "ml_detected_anomalies": [
      {
        "type": "ml_detected",
        "description": "Machine learning model detected CPU usage anomaly",
        "score": -0.42,
        "severity": "high"
      },
      {
        "type": "io_wait_spike",
        "description": "Unusual I/O wait time spike: 35.2% (avg: 5.8%)",
        "severity": "high"
      }
    ]
  },
  "correlation_anomalies": [
    {
      "type": "disk_io_anomaly",
      "description": "High disk I/O without corresponding CPU usage (possible data exfiltration)",
      "severity": "critical"
    }
  ],
  "resource_trends": {
    "cpu_trend": "rapidly_increasing",
    "memory_trend": "stable",
    "disk_trend": "increasing",
    "cpu_slope": 25.3,
    "memory_slope": 3.2,
    "disk_slope": 8.7,
    "is_anomalous": true
  }
}
```

### Future Enhancements

Planned future enhancements to the ML-based analysis include:

1. **Supervised Learning Models** - Adding the ability to train models based on known attack patterns
2. **Deep Learning Integration** - Incorporating LSTM networks for sequence-based anomaly detection
3. **Multi-system Analysis** - Correlating patterns across multiple systems
4. **Automated Response** - Suggesting mitigation actions based on detected patterns
5. **User Feedback Loop** - Incorporating user feedback on false positives/negatives

## Advanced Behavior Anomaly Detection Features

### Process Behavior Analysis

The process behavior analysis detects abnormal process activity including:

- Unusual resource usage patterns
- Suspicious execution paths
- Abnormal network activities by processes
- Unusual process creation patterns
- Suspicious parent-child relationships
- Cryptomining and other malicious activities

Key features extracted from processes include:

- CPU and memory usage patterns
- I/O operations statistics
- Network connection count and types
- Process lifetime and execution context
- Command-line arguments and parameters
- Execution paths and ownership

### User Behavior Analysis

The user behavior analysis identifies abnormal user activities:

- Unusual login times or source locations
- Privilege escalation attempts
- Suspicious command execution patterns
- Access to sensitive files or resources
- Unusual session durations
- Login failure patterns

Key features tracked for user behavior include:

- Login time distribution
- Source IP address history
- Command execution frequency and types
- Privilege usage patterns
- File access patterns
- Session duration statistics

### File System Behavior Analysis

The file system behavior analysis detects suspicious file activities:

- Modification of critical system files
- Creation of files in suspicious locations
- Unusual permission or ownership changes
- Access patterns to sensitive files
- Suspicious file extension or type changes
- Abnormal file growth patterns

Key file behavior features include:

- Operation type (read, write, execute, delete)
- Path sensitivity classification
- File size and growth metrics
- User/owner identity
- Hidden file indicators
- Permission settings
- Timestamp patterns
- Access frequency

### Network Behavior Analysis

The network behavior analysis identifies abnormal network activities:

- Unusual connection patterns
- Data exfiltration attempts
- Command and control communications
- Beaconing or periodic connections
- Connections to suspicious destinations
- Abnormal data transfer volumes

Network behavior features include:

- Connection protocol and type
- Remote port and known service mapping
- Data transfer volume
- Connection duration
- Connection frequency
- Packet size distribution
- Encryption indicators
- Geographic location indicators

### Configuration Options

The behavior anomaly detection system is highly configurable:

```yaml
behavior_monitor:
  # Core settings
  continuous_monitoring: true
  report_interval: 300
  baseline_path: "/var/lib/sharpeye/baselines/behavior"
  auto_baseline: true
  baseline_duration: 60
  alert_threshold: 0.8
  
  # Monitor settings
  process_monitor:
    enabled: true
    scan_interval: 30
  
  file_monitor:
    enabled: true
    monitored_paths:
      - "/etc"
      - "/bin"
      - "/sbin"
    excluded_paths:
      - "/var/log/sharpeye"
  
  # Behavior analyzer settings
  analyzer:
    history_size: 1000
    n_estimators: 100
    contamination: 0.05
```

### Integration with Threat Intelligence

The behavior anomaly detection system integrates with SharpEye's threat intelligence functionality:

1. Network connections are checked against known malicious IP addresses
2. File operations are correlated with known malware signatures
3. Process behaviors are matched against known attack patterns
4. User behaviors are analyzed for known compromise indicators

This integration enhances detection capabilities by providing additional context for anomaly evaluation.

## Using ML Analysis in Other Modules

The machine learning approaches implemented in SharpEye provide a comprehensive framework that enhances all security modules:

- **User Account Module** - Enhanced with user behavior anomaly detection
- **Network Module** - Enriched with network behavior pattern analysis
- **Process Module** - Upgraded with process behavior anomaly detection
- **SSH Module** - Improved with login pattern analysis and behavior tracking
- **Rootkit Detection** - Strengthened with sophisticated behavior-based detection
- **Cryptominer Detection** - Enhanced with statistical pattern recognition

The behavior anomaly detection system provides a unified approach that connects and correlates findings across all modules, significantly improving detection capabilities.

## Requirements

The machine learning capabilities require the following Python packages:
- numpy
- scikit-learn
- pandas
- scipy
- psutil (for live system data collection)

These dependencies are included in the SharpEye requirements.txt file.

## Performance Considerations

The behavior anomaly detection system is designed to be efficient and scalable:

- Memory usage is controlled through configurable history limits
- CPU usage is optimized by using efficient algorithms
- Storage requirements are minimal, with baselines stored in compact JSON format
- Resource consumption can be fine-tuned through configuration parameters

## Future Enhancements

Planned enhancements for the behavior anomaly detection system include:

1. **Deep Learning Models** - Adding neural network-based detection for complex patterns
2. **Multi-system Correlation** - Analyzing behavior across multiple systems
3. **Adversarial Analysis** - Detecting evasion techniques used by advanced threats
4. **Behavioral Fingerprinting** - Developing unique signatures for known attack patterns
5. **Adaptive Thresholding** - Automatically adjusting detection thresholds based on system environment