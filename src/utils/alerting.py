#!/usr/bin/env python3
"""
Real-time Alerting System for SharpEye
Provides multiple alert channels and intelligent alert management
"""

import os
import json
import logging
import smtplib
import requests
import threading
import queue
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict
import hashlib
import subprocess
import socket

logger = logging.getLogger('sharpeye.alerting')


class AlertPriority:
    """Alert priority levels"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'
    
    @staticmethod
    def get_numeric_value(priority: str) -> int:
        """Get numeric value for priority comparison"""
        priority_map = {
            AlertPriority.CRITICAL: 5,
            AlertPriority.HIGH: 4,
            AlertPriority.MEDIUM: 3,
            AlertPriority.LOW: 2,
            AlertPriority.INFO: 1
        }
        return priority_map.get(priority, 0)


class Alert:
    """Represents a security alert"""
    
    def __init__(self, 
                 alert_id: str,
                 title: str,
                 description: str,
                 priority: str,
                 source: str,
                 category: str,
                 data: Dict = None,
                 actions: List[str] = None):
        self.alert_id = alert_id
        self.title = title
        self.description = description
        self.priority = priority
        self.source = source
        self.category = category
        self.data = data or {}
        self.actions = actions or []
        self.timestamp = datetime.now()
        self.acknowledged = False
        self.resolved = False
        
    def to_dict(self) -> Dict:
        """Convert alert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'source': self.source,
            'category': self.category,
            'data': self.data,
            'actions': self.actions,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged,
            'resolved': self.resolved
        }
    
    def get_hash(self) -> str:
        """Get unique hash for alert deduplication"""
        content = f"{self.source}:{self.category}:{self.title}"
        return hashlib.md5(content.encode()).hexdigest()[:16]


class AlertChannel:
    """Base class for alert channels"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        self.min_priority = self.config.get('min_priority', AlertPriority.MEDIUM)
        self.rate_limit = self.config.get('rate_limit', 10)  # alerts per minute
        self.last_alert_time = {}
        
    def should_send(self, alert: Alert) -> bool:
        """Check if alert should be sent through this channel"""
        if not self.enabled:
            return False
            
        # Check priority threshold
        alert_priority_value = AlertPriority.get_numeric_value(alert.priority)
        min_priority_value = AlertPriority.get_numeric_value(self.min_priority)
        
        if alert_priority_value < min_priority_value:
            return False
            
        # Check rate limiting
        now = time.time()
        minute_key = int(now / 60)
        
        if minute_key not in self.last_alert_time:
            self.last_alert_time = {minute_key: 0}
            
        if self.last_alert_time.get(minute_key, 0) >= self.rate_limit:
            logger.warning(f"Rate limit exceeded for {self.__class__.__name__}")
            return False
            
        return True
    
    def send(self, alert: Alert) -> bool:
        """Send alert through channel"""
        raise NotImplementedError("Subclasses must implement send method")


class EmailAlertChannel(AlertChannel):
    """Email alert channel"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.smtp_server = self.config.get('smtp_server', 'localhost')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.use_tls = self.config.get('use_tls', True)
        self.username = self.config.get('username', '')
        self.password = self.config.get('password', '')
        self.from_address = self.config.get('from_address', 'sharpeye@localhost')
        self.to_addresses = self.config.get('to_addresses', [])
        
    def send(self, alert: Alert) -> bool:
        """Send alert via email"""
        if not self.should_send(alert):
            return False
            
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[SharpEye] {alert.priority.upper()}: {alert.title}"
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            
            # Create HTML content
            html_content = self._create_html_content(alert)
            
            # Create plain text content
            text_content = self._create_text_content(alert)
            
            # Attach parts
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            if self.smtp_server:
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls()
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.send_message(msg)
                    
                logger.info(f"Email alert sent for {alert.alert_id}")
                
                # Update rate limiting
                now = time.time()
                minute_key = int(now / 60)
                self.last_alert_time[minute_key] = self.last_alert_time.get(minute_key, 0) + 1
                
                return True
            else:
                logger.warning("SMTP server not configured")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
            return False
    
    def _create_html_content(self, alert: Alert) -> str:
        """Create HTML email content"""
        priority_colors = {
            AlertPriority.CRITICAL: '#FF0000',
            AlertPriority.HIGH: '#FF8C00',
            AlertPriority.MEDIUM: '#FFD700',
            AlertPriority.LOW: '#00CED1',
            AlertPriority.INFO: '#4169E1'
        }
        
        color = priority_colors.get(alert.priority, '#808080')
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: {color}; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .data {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; }}
                .actions {{ margin-top: 20px; }}
                .action {{ background-color: #e0e0e0; padding: 5px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>SharpEye Security Alert</h2>
                <h3>{alert.title}</h3>
            </div>
            <div class="content">
                <p><strong>Priority:</strong> {alert.priority.upper()}</p>
                <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Source:</strong> {alert.source}</p>
                <p><strong>Category:</strong> {alert.category}</p>
                
                <h4>Description</h4>
                <p>{alert.description}</p>
                
                <h4>Alert Data</h4>
                <div class="data">
                    <pre>{json.dumps(alert.data, indent=2)}</pre>
                </div>
                
                <div class="actions">
                    <h4>Recommended Actions</h4>
                    {''.join(f'<div class="action">{action}</div>' for action in alert.actions)}
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_text_content(self, alert: Alert) -> str:
        """Create plain text email content"""
        text = f"""
SharpEye Security Alert
======================

Title: {alert.title}
Priority: {alert.priority.upper()}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Source: {alert.source}
Category: {alert.category}

Description:
{alert.description}

Alert Data:
{json.dumps(alert.data, indent=2)}

Recommended Actions:
{''.join(f'- {action}' + chr(10) for action in alert.actions)}
Alert ID: {alert.alert_id}
        """
        
        return text


class SlackAlertChannel(AlertChannel):
    """Slack alert channel"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.webhook_url = self.config.get('webhook_url', '')
        self.channel = self.config.get('channel', '#alerts')
        self.username = self.config.get('username', 'SharpEye')
        
    def send(self, alert: Alert) -> bool:
        """Send alert to Slack"""
        if not self.should_send(alert) or not self.webhook_url:
            return False
            
        try:
            # Create Slack message
            priority_emojis = {
                AlertPriority.CRITICAL: '🚨',
                AlertPriority.HIGH: '⚠️',
                AlertPriority.MEDIUM: '⚡',
                AlertPriority.LOW: 'ℹ️',
                AlertPriority.INFO: '💡'
            }
            
            emoji = priority_emojis.get(alert.priority, '📢')
            
            payload = {
                'channel': self.channel,
                'username': self.username,
                'icon_emoji': ':shield:',
                'attachments': [{
                    'color': self._get_slack_color(alert.priority),
                    'title': f"{emoji} {alert.title}",
                    'text': alert.description,
                    'fields': [
                        {'title': 'Priority', 'value': alert.priority.upper(), 'short': True},
                        {'title': 'Source', 'value': alert.source, 'short': True},
                        {'title': 'Category', 'value': alert.category, 'short': True},
                        {'title': 'Time', 'value': alert.timestamp.strftime('%H:%M:%S'), 'short': True}
                    ],
                    'footer': f"Alert ID: {alert.alert_id}",
                    'ts': int(alert.timestamp.timestamp())
                }]
            }
            
            # Add actions if present
            if alert.actions:
                payload['attachments'][0]['fields'].append({
                    'title': 'Recommended Actions',
                    'value': '\n'.join(f"• {action}" for action in alert.actions),
                    'short': False
                })
            
            # Send to Slack
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info(f"Slack alert sent for {alert.alert_id}")
            
            # Update rate limiting
            now = time.time()
            minute_key = int(now / 60)
            self.last_alert_time[minute_key] = self.last_alert_time.get(minute_key, 0) + 1
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}")
            return False
    
    def _get_slack_color(self, priority: str) -> str:
        """Get Slack attachment color based on priority"""
        colors = {
            AlertPriority.CRITICAL: 'danger',
            AlertPriority.HIGH: 'warning',
            AlertPriority.MEDIUM: '#FFD700',
            AlertPriority.LOW: '#00CED1',
            AlertPriority.INFO: 'good'
        }
        return colors.get(priority, '#808080')


class WebhookAlertChannel(AlertChannel):
    """Generic webhook alert channel"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.url = self.config.get('url', '')
        self.method = self.config.get('method', 'POST')
        self.headers = self.config.get('headers', {})
        self.timeout = self.config.get('timeout', 10)
        
    def send(self, alert: Alert) -> bool:
        """Send alert to webhook"""
        if not self.should_send(alert) or not self.url:
            return False
            
        try:
            # Prepare payload
            payload = {
                'alert': alert.to_dict(),
                'hostname': socket.gethostname(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Send request
            response = requests.request(
                method=self.method,
                url=self.url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            logger.info(f"Webhook alert sent for {alert.alert_id}")
            
            # Update rate limiting
            now = time.time()
            minute_key = int(now / 60)
            self.last_alert_time[minute_key] = self.last_alert_time.get(minute_key, 0) + 1
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {str(e)}")
            return False


class SyslogAlertChannel(AlertChannel):
    """Syslog alert channel"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.facility = self.config.get('facility', 'local0')
        self.priority_map = self.config.get('priority_map', {})
        
    def send(self, alert: Alert) -> bool:
        """Send alert to syslog"""
        if not self.should_send(alert):
            return False
            
        try:
            # Map alert priority to syslog priority
            syslog_priorities = {
                AlertPriority.CRITICAL: 'crit',
                AlertPriority.HIGH: 'err',
                AlertPriority.MEDIUM: 'warning',
                AlertPriority.LOW: 'notice',
                AlertPriority.INFO: 'info'
            }
            
            priority = self.priority_map.get(alert.priority, 
                                           syslog_priorities.get(alert.priority, 'info'))
            
            # Create syslog message
            message = f"SharpEye Alert [{alert.alert_id}] {alert.priority.upper()}: {alert.title} - {alert.description}"
            
            # Send to syslog using logger command
            cmd = ['logger', '-p', f"{self.facility}.{priority}", '-t', 'sharpeye', message]
            subprocess.run(cmd, check=True)
            
            logger.info(f"Syslog alert sent for {alert.alert_id}")
            
            # Update rate limiting
            now = time.time()
            minute_key = int(now / 60)
            self.last_alert_time[minute_key] = self.last_alert_time.get(minute_key, 0) + 1
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send syslog alert: {str(e)}")
            return False


class AlertManager:
    """Manages alerts and alert channels"""
    
    def __init__(self, config: Dict = None):
        """Initialize alert manager"""
        self.config = config or {}
        self.logger = logger
        
        # Initialize alert channels
        self.channels = {}
        self._init_channels()
        
        # Alert queue for async processing
        self.alert_queue = queue.Queue()
        self.processing = False
        self.processing_thread = None
        
        # Alert deduplication
        self.recent_alerts = {}
        self.dedup_window = timedelta(minutes=self.config.get('dedup_window_minutes', 5))
        
        # Alert storage
        self.alert_history = []
        self.max_history = self.config.get('max_history', 1000)
        
        # Alert callbacks
        self.callbacks = []
        
        # Start processing thread
        self.start()
        
        self.logger.info("Alert manager initialized")
    
    def _init_channels(self):
        """Initialize configured alert channels"""
        channels_config = self.config.get('channels', {})
        
        # Email channel
        if channels_config.get('email', {}).get('enabled', False):
            self.channels['email'] = EmailAlertChannel(channels_config['email'])
            self.logger.info("Email alert channel enabled")
            
        # Slack channel
        if channels_config.get('slack', {}).get('enabled', False):
            self.channels['slack'] = SlackAlertChannel(channels_config['slack'])
            self.logger.info("Slack alert channel enabled")
            
        # Webhook channel
        if channels_config.get('webhook', {}).get('enabled', False):
            self.channels['webhook'] = WebhookAlertChannel(channels_config['webhook'])
            self.logger.info("Webhook alert channel enabled")
            
        # Syslog channel
        if channels_config.get('syslog', {}).get('enabled', False):
            self.channels['syslog'] = SyslogAlertChannel(channels_config['syslog'])
            self.logger.info("Syslog alert channel enabled")
    
    def create_alert(self,
                    title: str,
                    description: str,
                    priority: str = AlertPriority.MEDIUM,
                    source: str = 'unknown',
                    category: str = 'general',
                    data: Dict = None,
                    actions: List[str] = None) -> Alert:
        """Create a new alert"""
        # Generate alert ID
        alert_id = f"{int(time.time() * 1000)}_{hashlib.md5(title.encode()).hexdigest()[:8]}"
        
        alert = Alert(
            alert_id=alert_id,
            title=title,
            description=description,
            priority=priority,
            source=source,
            category=category,
            data=data,
            actions=actions
        )
        
        return alert
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert through configured channels"""
        # Check for duplicate alerts
        alert_hash = alert.get_hash()
        now = datetime.now()
        
        if alert_hash in self.recent_alerts:
            last_sent = self.recent_alerts[alert_hash]
            if now - last_sent < self.dedup_window:
                self.logger.debug(f"Duplicate alert suppressed: {alert.alert_id}")
                return False
        
        # Add to queue for async processing
        self.alert_queue.put(alert)
        
        # Update deduplication cache
        self.recent_alerts[alert_hash] = now
        
        # Clean old entries from dedup cache
        cutoff_time = now - self.dedup_window
        self.recent_alerts = {k: v for k, v in self.recent_alerts.items() 
                            if v > cutoff_time}
        
        return True
    
    def _process_alerts(self):
        """Process alerts from queue"""
        while self.processing:
            try:
                # Get alert from queue with timeout
                alert = self.alert_queue.get(timeout=1)
                
                # Send through all configured channels
                success_count = 0
                for channel_name, channel in self.channels.items():
                    try:
                        if channel.send(alert):
                            success_count += 1
                            self.logger.debug(f"Alert sent through {channel_name}")
                    except Exception as e:
                        self.logger.error(f"Error sending alert through {channel_name}: {str(e)}")
                
                # Store in history
                self._store_alert(alert)
                
                # Execute callbacks
                for callback in self.callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self.logger.error(f"Error in alert callback: {str(e)}")
                
                # Mark as processed
                self.alert_queue.task_done()
                
                if success_count > 0:
                    self.logger.info(f"Alert {alert.alert_id} sent through {success_count} channels")
                else:
                    self.logger.warning(f"Alert {alert.alert_id} could not be sent through any channel")
                    
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing alert: {str(e)}")
    
    def _store_alert(self, alert: Alert):
        """Store alert in history"""
        self.alert_history.append(alert)
        
        # Trim history if needed
        if len(self.alert_history) > self.max_history:
            self.alert_history = self.alert_history[-self.max_history:]
    
    def register_callback(self, callback: Callable[[Alert], None]):
        """Register a callback to be called when alerts are sent"""
        self.callbacks.append(callback)
    
    def get_recent_alerts(self, hours: int = 24, 
                         priority: Optional[str] = None,
                         category: Optional[str] = None) -> List[Alert]:
        """Get recent alerts with optional filtering"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        filtered_alerts = []
        for alert in reversed(self.alert_history):
            if alert.timestamp < cutoff_time:
                break
                
            if priority and alert.priority != priority:
                continue
                
            if category and alert.category != category:
                continue
                
            filtered_alerts.append(alert)
        
        return filtered_alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        stats = {
            'total_alerts': len(self.alert_history),
            'queued_alerts': self.alert_queue.qsize(),
            'channels_enabled': len(self.channels),
            'by_priority': defaultdict(int),
            'by_category': defaultdict(int),
            'by_source': defaultdict(int)
        }
        
        # Count alerts by various dimensions
        for alert in self.alert_history:
            stats['by_priority'][alert.priority] += 1
            stats['by_category'][alert.category] += 1
            stats['by_source'][alert.source] += 1
        
        # Convert defaultdicts to regular dicts
        stats['by_priority'] = dict(stats['by_priority'])
        stats['by_category'] = dict(stats['by_category'])
        stats['by_source'] = dict(stats['by_source'])
        
        return stats
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        for alert in self.alert_history:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved"""
        for alert in self.alert_history:
            if alert.alert_id == alert_id:
                alert.resolved = True
                return True
        return False
    
    def start(self):
        """Start alert processing"""
        if not self.processing:
            self.processing = True
            self.processing_thread = threading.Thread(
                target=self._process_alerts,
                daemon=True,
                name="AlertProcessor"
            )
            self.processing_thread.start()
            self.logger.info("Alert processing started")
    
    def stop(self):
        """Stop alert processing"""
        if self.processing:
            self.processing = False
            if self.processing_thread:
                self.processing_thread.join(timeout=5)
            self.logger.info("Alert processing stopped")


# Singleton instance
_alert_manager_instance = None


def get_alert_manager(config: Dict = None) -> AlertManager:
    """Get or create alert manager singleton"""
    global _alert_manager_instance
    
    if _alert_manager_instance is None:
        _alert_manager_instance = AlertManager(config)
    
    return _alert_manager_instance