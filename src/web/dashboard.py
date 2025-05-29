#!/usr/bin/env python3
"""
Web Dashboard for SharpEye
Provides real-time visualization and control interface
"""

import os
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psutil
from typing import Dict, List, Any, Optional
import queue

# Import SharpEye modules
from ..utils.alerting import get_alert_manager, AlertPriority
from ..modules.behavior_monitor import BehaviorMonitor
from ..modules.advanced_threat_detector import AdvancedThreatDetector

logger = logging.getLogger('sharpeye.dashboard')


class DashboardServer:
    """Web dashboard server for SharpEye"""
    
    def __init__(self, config: Dict = None):
        """Initialize dashboard server"""
        self.config = config or {}
        self.app = Flask(__name__, 
                        static_folder='static',
                        template_folder='templates')
        
        # Configure Flask
        self.app.config['SECRET_KEY'] = self.config.get('secret_key', 'sharpeye-dashboard-secret')
        
        # Enable CORS
        CORS(self.app, resources={r"/api/*": {"origins": "*"}})
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Dashboard state
        self.start_time = datetime.now()
        self.alert_manager = get_alert_manager()
        self.behavior_monitor = None
        self.threat_detector = None
        self.update_queue = queue.Queue()
        
        # Metrics cache
        self.metrics_cache = {
            'system': {},
            'threats': {},
            'alerts': {},
            'modules': {}
        }
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio()
        
        # Start background threads
        self._start_metric_collector()
        self._start_update_broadcaster()
        
        logger.info("Dashboard server initialized")
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('index.html')
        
        @self.app.route('/api/status')
        def api_status():
            """Get system status"""
            uptime = (datetime.now() - self.start_time).total_seconds()
            
            status = {
                'status': 'operational',
                'uptime': uptime,
                'version': '1.0.0',
                'modules': self._get_module_status(),
                'timestamp': datetime.now().isoformat()
            }
            
            return jsonify(status)
        
        @self.app.route('/api/metrics')
        def api_metrics():
            """Get system metrics"""
            return jsonify(self.metrics_cache)
        
        @self.app.route('/api/alerts')
        def api_alerts():
            """Get recent alerts"""
            hours = request.args.get('hours', 24, type=int)
            priority = request.args.get('priority')
            category = request.args.get('category')
            
            alerts = self.alert_manager.get_recent_alerts(
                hours=hours,
                priority=priority,
                category=category
            )
            
            return jsonify({
                'alerts': [alert.to_dict() for alert in alerts],
                'total': len(alerts),
                'statistics': self.alert_manager.get_statistics()
            })
        
        @self.app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
        def acknowledge_alert(alert_id):
            """Acknowledge an alert"""
            success = self.alert_manager.acknowledge_alert(alert_id)
            return jsonify({'success': success})
        
        @self.app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
        def resolve_alert(alert_id):
            """Resolve an alert"""
            success = self.alert_manager.resolve_alert(alert_id)
            return jsonify({'success': success})
        
        @self.app.route('/api/threats')
        def api_threats():
            """Get threat analysis results"""
            if self.threat_detector:
                results = self.threat_detector.analyze()
                return jsonify(results)
            else:
                return jsonify({'error': 'Threat detector not initialized'}), 503
        
        @self.app.route('/api/behavior')
        def api_behavior():
            """Get behavior monitoring data"""
            if self.behavior_monitor:
                status = self.behavior_monitor.get_status()
                return jsonify(status)
            else:
                return jsonify({'error': 'Behavior monitor not initialized'}), 503
        
        @self.app.route('/api/modules/<module_name>/start', methods=['POST'])
        def start_module(module_name):
            """Start a specific module"""
            # Implementation depends on module management
            return jsonify({'status': 'not_implemented'}), 501
        
        @self.app.route('/api/modules/<module_name>/stop', methods=['POST'])
        def stop_module(module_name):
            """Stop a specific module"""
            # Implementation depends on module management
            return jsonify({'status': 'not_implemented'}), 501
        
        @self.app.route('/api/export/<report_type>')
        def export_report(report_type):
            """Export reports in various formats"""
            format_type = request.args.get('format', 'json')
            
            if report_type == 'alerts':
                data = self.alert_manager.get_recent_alerts()
                # Convert to requested format
                if format_type == 'json':
                    return jsonify([alert.to_dict() for alert in data])
                elif format_type == 'csv':
                    # Convert to CSV
                    csv_data = self._convert_to_csv(data)
                    return Response(
                        csv_data,
                        mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename={report_type}.csv'}
                    )
            
            return jsonify({'error': 'Invalid report type'}), 400
    
    def _setup_socketio(self):
        """Setup SocketIO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            logger.info(f"Client connected: {request.sid}")
            emit('connected', {'data': 'Connected to SharpEye Dashboard'})
            
            # Send initial data
            emit('metrics_update', self.metrics_cache)
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            logger.info(f"Client disconnected: {request.sid}")
        
        @self.socketio.on('request_update')
        def handle_update_request(data):
            """Handle update request from client"""
            update_type = data.get('type', 'all')
            
            if update_type == 'metrics':
                emit('metrics_update', self.metrics_cache)
            elif update_type == 'alerts':
                alerts = self.alert_manager.get_recent_alerts(hours=1)
                emit('alerts_update', {
                    'alerts': [alert.to_dict() for alert in alerts]
                })
    
    def _start_metric_collector(self):
        """Start background thread to collect metrics"""
        def collect_metrics():
            while True:
                try:
                    # Collect system metrics
                    self.metrics_cache['system'] = {
                        'cpu_percent': psutil.cpu_percent(interval=1),
                        'memory': psutil.virtual_memory()._asdict(),
                        'disk': psutil.disk_usage('/')._asdict(),
                        'network': psutil.net_io_counters()._asdict(),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Collect process metrics
                    processes = []
                    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                        try:
                            proc_info = proc.info
                            if proc_info['cpu_percent'] > 5:  # Only high CPU processes
                                processes.append(proc_info)
                        except:
                            continue
                    
                    self.metrics_cache['processes'] = sorted(
                        processes, 
                        key=lambda x: x['cpu_percent'],
                        reverse=True
                    )[:10]  # Top 10 processes
                    
                    # Queue update for broadcast
                    self.update_queue.put(('metrics', self.metrics_cache))
                    
                    time.sleep(5)  # Update every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Error collecting metrics: {str(e)}")
                    time.sleep(10)
        
        thread = threading.Thread(target=collect_metrics, daemon=True)
        thread.start()
    
    def _start_update_broadcaster(self):
        """Start background thread to broadcast updates"""
        def broadcast_updates():
            while True:
                try:
                    # Get update from queue
                    update_type, data = self.update_queue.get(timeout=1)
                    
                    # Broadcast to all connected clients
                    if update_type == 'metrics':
                        self.socketio.emit('metrics_update', data)
                    elif update_type == 'alert':
                        self.socketio.emit('new_alert', data)
                    elif update_type == 'threat':
                        self.socketio.emit('threat_update', data)
                    
                    self.update_queue.task_done()
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Error broadcasting update: {str(e)}")
        
        thread = threading.Thread(target=broadcast_updates, daemon=True)
        thread.start()
    
    def _get_module_status(self) -> Dict[str, Any]:
        """Get status of all modules"""
        modules = {
            'behavior_monitor': {
                'enabled': self.behavior_monitor is not None,
                'status': 'running' if self.behavior_monitor and self.behavior_monitor.running else 'stopped'
            },
            'threat_detector': {
                'enabled': self.threat_detector is not None,
                'status': 'active' if self.threat_detector else 'inactive'
            },
            'alert_manager': {
                'enabled': True,
                'status': 'active',
                'stats': self.alert_manager.get_statistics()
            }
        }
        
        return modules
    
    def _convert_to_csv(self, data: List[Any]) -> str:
        """Convert data to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        
        if not data:
            return ""
        
        # Get headers from first item
        if hasattr(data[0], 'to_dict'):
            headers = list(data[0].to_dict().keys())
            writer = csv.DictWriter(output, fieldnames=headers)
            writer.writeheader()
            
            for item in data:
                writer.writerow(item.to_dict())
        else:
            # Handle dict data
            headers = list(data[0].keys())
            writer = csv.DictWriter(output, fieldnames=headers)
            writer.writeheader()
            
            for item in data:
                writer.writerow(item)
        
        return output.getvalue()
    
    def set_behavior_monitor(self, monitor: BehaviorMonitor):
        """Set behavior monitor instance"""
        self.behavior_monitor = monitor
        
        # Register alert callback
        def on_behavior_alert(anomaly):
            alert = self.alert_manager.create_alert(
                title=f"Behavior Anomaly: {anomaly.get('type')}",
                description=f"Anomalous behavior detected in {anomaly.get('category')}",
                priority=anomaly.get('severity', AlertPriority.MEDIUM),
                source='behavior_monitor',
                category='behavior',
                data=anomaly
            )
            self.alert_manager.send_alert(alert)
            self.update_queue.put(('alert', alert.to_dict()))
        
        # This would need to be implemented in BehaviorMonitor
        # self.behavior_monitor.register_callback(on_behavior_alert)
    
    def set_threat_detector(self, detector: AdvancedThreatDetector):
        """Set threat detector instance"""
        self.threat_detector = detector
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """Run the dashboard server"""
        logger.info(f"Starting dashboard server on {host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)


def create_dashboard_app(config: Dict = None) -> DashboardServer:
    """Create and configure dashboard application"""
    dashboard = DashboardServer(config)
    return dashboard


# HTML Templates (would normally be in separate files)
def create_template_files():
    """Create basic template files for the dashboard"""
    
    # Create directories
    os.makedirs('src/web/templates', exist_ok=True)
    os.makedirs('src/web/static/css', exist_ok=True)
    os.makedirs('src/web/static/js', exist_ok=True)
    
    # Basic HTML template
    index_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SharpEye Dashboard</title>
    <link rel="stylesheet" href="/static/css/dashboard.css">
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>SharpEye Security Dashboard</h1>
            <div class="status-bar">
                <span id="connection-status">Disconnected</span>
                <span id="system-time"></span>
            </div>
        </header>
        
        <div class="dashboard-grid">
            <div class="widget" id="system-metrics">
                <h2>System Metrics</h2>
                <canvas id="cpu-chart"></canvas>
                <div class="metric-values">
                    <div class="metric">
                        <span class="label">CPU:</span>
                        <span class="value" id="cpu-value">0%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Memory:</span>
                        <span class="value" id="memory-value">0%</span>
                    </div>
                    <div class="metric">
                        <span class="label">Disk:</span>
                        <span class="value" id="disk-value">0%</span>
                    </div>
                </div>
            </div>
            
            <div class="widget" id="alerts">
                <h2>Recent Alerts</h2>
                <div id="alert-list"></div>
            </div>
            
            <div class="widget" id="threats">
                <h2>Threat Status</h2>
                <div id="threat-summary">
                    <div class="threat-score">
                        <span class="label">Risk Score:</span>
                        <span class="value" id="risk-score">0.0</span>
                    </div>
                </div>
            </div>
            
            <div class="widget" id="modules">
                <h2>Module Status</h2>
                <div id="module-list"></div>
            </div>
        </div>
    </div>
    
    <script src="/static/js/dashboard.js"></script>
</body>
</html>"""
    
    # Basic CSS
    dashboard_css = """
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 0;
    background-color: #0a0e27;
    color: #e0e0e0;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 1px solid #2a3f5f;
}

h1 {
    margin: 0;
    color: #00d4ff;
}

.status-bar {
    display: flex;
    gap: 20px;
    font-size: 14px;
}

#connection-status {
    padding: 5px 10px;
    border-radius: 4px;
    background-color: #ff4444;
}

#connection-status.connected {
    background-color: #44ff44;
    color: #000;
}

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
}

.widget {
    background-color: #1a1f3a;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
}

.widget h2 {
    margin-top: 0;
    color: #00d4ff;
    font-size: 18px;
}

.metric-values {
    display: flex;
    justify-content: space-around;
    margin-top: 20px;
}

.metric {
    text-align: center;
}

.metric .label {
    display: block;
    font-size: 12px;
    color: #888;
    margin-bottom: 5px;
}

.metric .value {
    display: block;
    font-size: 24px;
    font-weight: bold;
    color: #00d4ff;
}

#alert-list {
    max-height: 300px;
    overflow-y: auto;
}

.alert-item {
    padding: 10px;
    margin-bottom: 10px;
    border-radius: 4px;
    background-color: #2a3f5f;
}

.alert-item.critical {
    border-left: 4px solid #ff4444;
}

.alert-item.high {
    border-left: 4px solid #ff8844;
}

.alert-item.medium {
    border-left: 4px solid #ffdd44;
}

.threat-score {
    text-align: center;
    padding: 20px;
}

.threat-score .value {
    font-size: 48px;
    font-weight: bold;
}
"""
    
    # Basic JavaScript
    dashboard_js = """
const socket = io();

// Connection status
socket.on('connect', () => {
    document.getElementById('connection-status').textContent = 'Connected';
    document.getElementById('connection-status').classList.add('connected');
});

socket.on('disconnect', () => {
    document.getElementById('connection-status').textContent = 'Disconnected';
    document.getElementById('connection-status').classList.remove('connected');
});

// Update system time
setInterval(() => {
    document.getElementById('system-time').textContent = new Date().toLocaleString();
}, 1000);

// Initialize CPU chart
const ctx = document.getElementById('cpu-chart').getContext('2d');
const cpuChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'CPU Usage',
            data: [],
            borderColor: '#00d4ff',
            backgroundColor: 'rgba(0, 212, 255, 0.1)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        },
        plugins: {
            legend: {
                display: false
            }
        }
    }
});

// Handle metrics updates
socket.on('metrics_update', (data) => {
    if (data.system) {
        // Update metric values
        document.getElementById('cpu-value').textContent = data.system.cpu_percent.toFixed(1) + '%';
        document.getElementById('memory-value').textContent = data.system.memory.percent.toFixed(1) + '%';
        document.getElementById('disk-value').textContent = data.system.disk.percent.toFixed(1) + '%';
        
        // Update CPU chart
        const now = new Date().toLocaleTimeString();
        cpuChart.data.labels.push(now);
        cpuChart.data.datasets[0].data.push(data.system.cpu_percent);
        
        // Keep only last 20 data points
        if (cpuChart.data.labels.length > 20) {
            cpuChart.data.labels.shift();
            cpuChart.data.datasets[0].data.shift();
        }
        
        cpuChart.update('none');
    }
});

// Handle new alerts
socket.on('new_alert', (alert) => {
    addAlert(alert);
});

function addAlert(alert) {
    const alertList = document.getElementById('alert-list');
    const alertItem = document.createElement('div');
    alertItem.className = `alert-item ${alert.priority}`;
    alertItem.innerHTML = `
        <div class="alert-title">${alert.title}</div>
        <div class="alert-time">${new Date(alert.timestamp).toLocaleString()}</div>
    `;
    
    alertList.insertBefore(alertItem, alertList.firstChild);
    
    // Keep only last 10 alerts
    while (alertList.children.length > 10) {
        alertList.removeChild(alertList.lastChild);
    }
}

// Load initial data
fetch('/api/status')
    .then(response => response.json())
    .then(data => {
        updateModuleStatus(data.modules);
    });

fetch('/api/alerts?hours=1')
    .then(response => response.json())
    .then(data => {
        data.alerts.forEach(alert => addAlert(alert));
    });

function updateModuleStatus(modules) {
    const moduleList = document.getElementById('module-list');
    moduleList.innerHTML = '';
    
    for (const [name, status] of Object.entries(modules)) {
        const moduleItem = document.createElement('div');
        moduleItem.className = 'module-item';
        moduleItem.innerHTML = `
            <span class="module-name">${name}</span>
            <span class="module-status ${status.status}">${status.status}</span>
        `;
        moduleList.appendChild(moduleItem);
    }
}

// Request updates periodically
setInterval(() => {
    socket.emit('request_update', {type: 'metrics'});
}, 5000);
"""
    
    # Save files (this would be done during setup)
    # with open('src/web/templates/index.html', 'w') as f:
    #     f.write(index_html)
    # with open('src/web/static/css/dashboard.css', 'w') as f:
    #     f.write(dashboard_css)
    # with open('src/web/static/js/dashboard.js', 'w') as f:
    #     f.write(dashboard_js)