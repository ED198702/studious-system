// SharpEye Dashboard JavaScript

const socket = io();
let charts = {};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    setupSocketHandlers();
    loadInitialData();
    startClock();
});

// Initialize charts
function initializeCharts() {
    // CPU usage chart
    const cpuCtx = document.getElementById('cpu-chart').getContext('2d');
    charts.cpu = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU Usage',
                data: [],
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#888',
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#888',
                        maxRotation: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });

    // Network activity chart
    const networkCtx = document.getElementById('network-chart').getContext('2d');
    charts.network = new Chart(networkCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bytes Sent',
                data: [],
                borderColor: '#44ff44',
                backgroundColor: 'rgba(68, 255, 68, 0.1)',
                tension: 0.4,
                fill: false
            }, {
                label: 'Bytes Received',
                data: [],
                borderColor: '#ff8844',
                backgroundColor: 'rgba(255, 136, 68, 0.1)',
                tension: 0.4,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#888',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#888',
                        maxRotation: 0
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#e0e0e0'
                    }
                }
            }
        }
    });
}

// Setup socket handlers
function setupSocketHandlers() {
    // Connection status
    socket.on('connect', () => {
        updateConnectionStatus(true);
    });

    socket.on('disconnect', () => {
        updateConnectionStatus(false);
    });

    // Metrics updates
    socket.on('metrics_update', (data) => {
        updateMetrics(data);
    });

    // New alerts
    socket.on('new_alert', (alert) => {
        addAlert(alert);
        showNotification(alert);
    });

    // Threat updates
    socket.on('threat_update', (data) => {
        updateThreatInfo(data);
    });
}

// Update connection status
function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    if (connected) {
        statusEl.textContent = 'Connected';
        statusEl.classList.add('connected');
    } else {
        statusEl.textContent = 'Disconnected';
        statusEl.classList.remove('connected');
    }
}

// Update metrics
function updateMetrics(data) {
    if (data.system) {
        // Update metric values
        document.getElementById('cpu-value').textContent = data.system.cpu_percent.toFixed(1) + '%';
        document.getElementById('memory-value').textContent = data.system.memory.percent.toFixed(1) + '%';
        document.getElementById('disk-value').textContent = data.system.disk.percent.toFixed(1) + '%';
        
        // Update CPU chart
        const now = new Date().toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit' 
        });
        
        charts.cpu.data.labels.push(now);
        charts.cpu.data.datasets[0].data.push(data.system.cpu_percent);
        
        // Keep only last 30 data points
        if (charts.cpu.data.labels.length > 30) {
            charts.cpu.data.labels.shift();
            charts.cpu.data.datasets[0].data.shift();
        }
        
        charts.cpu.update('none');
        
        // Update network chart if available
        if (data.system.network) {
            updateNetworkChart(data.system.network);
        }
    }
}

// Update network chart
let lastNetworkData = null;
function updateNetworkChart(networkData) {
    const now = new Date().toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit'
    });
    
    if (lastNetworkData) {
        const bytesSent = networkData.bytes_sent - lastNetworkData.bytes_sent;
        const bytesRecv = networkData.bytes_recv - lastNetworkData.bytes_recv;
        
        charts.network.data.labels.push(now);
        charts.network.data.datasets[0].data.push(bytesSent);
        charts.network.data.datasets[1].data.push(bytesRecv);
        
        // Keep only last 20 data points
        if (charts.network.data.labels.length > 20) {
            charts.network.data.labels.shift();
            charts.network.data.datasets[0].data.shift();
            charts.network.data.datasets[1].data.shift();
        }
        
        charts.network.update('none');
    }
    
    lastNetworkData = networkData;
}

// Add alert to list
function addAlert(alert) {
    const alertList = document.getElementById('alert-list');
    const alertItem = document.createElement('div');
    alertItem.className = `alert-item ${alert.priority}`;
    alertItem.innerHTML = `
        <div class="alert-title">${escapeHtml(alert.title)}</div>
        <div class="alert-time">${new Date(alert.timestamp).toLocaleString()}</div>
    `;
    
    alertList.insertBefore(alertItem, alertList.firstChild);
    
    // Keep only last 20 alerts
    while (alertList.children.length > 20) {
        alertList.removeChild(alertList.lastChild);
    }
    
    // Add animation
    alertItem.style.opacity = '0';
    alertItem.style.transform = 'translateX(-20px)';
    setTimeout(() => {
        alertItem.style.transition = 'all 0.3s ease';
        alertItem.style.opacity = '1';
        alertItem.style.transform = 'translateX(0)';
    }, 10);
}

// Update threat information
function updateThreatInfo(data) {
    const riskScore = data.risk_score || 0;
    const scoreEl = document.getElementById('risk-score');
    scoreEl.textContent = riskScore.toFixed(2);
    
    // Update color based on risk level
    const threatScoreEl = document.querySelector('.threat-score');
    threatScoreEl.classList.remove('high', 'critical');
    
    if (riskScore >= 0.8) {
        threatScoreEl.classList.add('critical');
    } else if (riskScore >= 0.5) {
        threatScoreEl.classList.add('high');
    }
    
    // Update threat details
    const detailsEl = document.getElementById('threat-details');
    if (data.threats && data.threats.length > 0) {
        const threatList = data.threats.slice(0, 3).map(threat => 
            `<div class="threat-item">${escapeHtml(threat.name)}</div>`
        ).join('');
        detailsEl.innerHTML = threatList;
    }
}

// Update module status
function updateModuleStatus(modules) {
    const moduleList = document.getElementById('module-list');
    moduleList.innerHTML = '';
    
    for (const [name, status] of Object.entries(modules)) {
        const moduleItem = document.createElement('div');
        moduleItem.className = 'module-item';
        moduleItem.innerHTML = `
            <span class="module-name">${formatModuleName(name)}</span>
            <span class="module-status ${status.status}">${status.status}</span>
        `;
        moduleList.appendChild(moduleItem);
    }
}

// Load initial data
function loadInitialData() {
    // Load system status
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            updateModuleStatus(data.modules);
        })
        .catch(error => console.error('Error loading status:', error));
    
    // Load recent alerts
    fetch('/api/alerts?hours=1')
        .then(response => response.json())
        .then(data => {
            data.alerts.forEach(alert => addAlert(alert));
        })
        .catch(error => console.error('Error loading alerts:', error));
    
    // Request initial metrics
    socket.emit('request_update', {type: 'metrics'});
}

// Start clock
function startClock() {
    const updateTime = () => {
        const now = new Date();
        document.getElementById('system-time').textContent = now.toLocaleString();
    };
    
    updateTime();
    setInterval(updateTime, 1000);
}

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatModuleName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Show browser notification
function showNotification(alert) {
    if ('Notification' in window && Notification.permission === 'granted') {
        const notification = new Notification('SharpEye Alert', {
            body: alert.title,
            icon: '/static/img/icon.png',
            tag: alert.alert_id
        });
        
        notification.onclick = () => {
            window.focus();
            notification.close();
        };
    }
}

// Request notification permission
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}

// Periodic updates
setInterval(() => {
    socket.emit('request_update', {type: 'metrics'});
}, 5000);

// Auto-refresh alerts every minute
setInterval(() => {
    fetch('/api/alerts?hours=1')
        .then(response => response.json())
        .then(data => {
            const alertList = document.getElementById('alert-list');
            alertList.innerHTML = '';
            data.alerts.forEach(alert => addAlert(alert));
        })
        .catch(error => console.error('Error refreshing alerts:', error));
}, 60000);