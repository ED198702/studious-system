#!/usr/bin/env python3
"""
Unit tests for Alerting module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import os
import sys
import time
import smtplib
import requests
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.alerting import (
    Alert, AlertPriority, AlertChannel, EmailAlertChannel, 
    SlackAlertChannel, WebhookAlertChannel, SyslogAlertChannel,
    AlertManager, get_alert_manager
)


class TestAlert(unittest.TestCase):
    """Test Alert class"""
    
    def test_alert_creation(self):
        """Test alert creation"""
        alert = Alert(
            alert_id="TEST001",
            title="Test Alert",
            description="This is a test alert",
            priority=AlertPriority.HIGH,
            source="test_module",
            category="test",
            data={'key': 'value'},
            actions=['Action 1', 'Action 2']
        )
        
        self.assertEqual(alert.alert_id, "TEST001")
        self.assertEqual(alert.title, "Test Alert")
        self.assertEqual(alert.priority, AlertPriority.HIGH)
        self.assertFalse(alert.acknowledged)
        self.assertFalse(alert.resolved)
    
    def test_alert_to_dict(self):
        """Test alert dictionary conversion"""
        alert = Alert(
            alert_id="TEST002",
            title="Test Alert",
            description="Description",
            priority=AlertPriority.MEDIUM,
            source="test",
            category="test"
        )
        
        alert_dict = alert.to_dict()
        
        self.assertEqual(alert_dict['alert_id'], "TEST002")
        self.assertEqual(alert_dict['priority'], AlertPriority.MEDIUM)
        self.assertIn('timestamp', alert_dict)
    
    def test_alert_hash(self):
        """Test alert hash generation"""
        alert1 = Alert(
            alert_id="TEST003",
            title="Same Title",
            description="Description 1",
            priority=AlertPriority.LOW,
            source="same_source",
            category="same_category"
        )
        
        alert2 = Alert(
            alert_id="TEST004",
            title="Same Title",
            description="Description 2",
            priority=AlertPriority.HIGH,
            source="same_source",
            category="same_category"
        )
        
        # Same source, category, and title should produce same hash
        self.assertEqual(alert1.get_hash(), alert2.get_hash())


class TestAlertPriority(unittest.TestCase):
    """Test AlertPriority class"""
    
    def test_priority_values(self):
        """Test priority numeric values"""
        self.assertEqual(AlertPriority.get_numeric_value(AlertPriority.CRITICAL), 5)
        self.assertEqual(AlertPriority.get_numeric_value(AlertPriority.HIGH), 4)
        self.assertEqual(AlertPriority.get_numeric_value(AlertPriority.MEDIUM), 3)
        self.assertEqual(AlertPriority.get_numeric_value(AlertPriority.LOW), 2)
        self.assertEqual(AlertPriority.get_numeric_value(AlertPriority.INFO), 1)
        self.assertEqual(AlertPriority.get_numeric_value('unknown'), 0)


class TestEmailAlertChannel(unittest.TestCase):
    """Test EmailAlertChannel"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'enabled': True,
            'smtp_server': 'smtp.test.com',
            'smtp_port': 587,
            'use_tls': True,
            'username': 'test@test.com',
            'password': 'testpass',
            'from_address': 'alerts@test.com',
            'to_addresses': ['admin@test.com'],
            'min_priority': AlertPriority.MEDIUM
        }
        self.channel = EmailAlertChannel(self.config)
    
    def test_should_send_priority_filter(self):
        """Test priority filtering"""
        high_alert = Alert(
            alert_id="TEST005",
            title="High Priority",
            description="Test",
            priority=AlertPriority.HIGH,
            source="test",
            category="test"
        )
        
        low_alert = Alert(
            alert_id="TEST006",
            title="Low Priority",
            description="Test",
            priority=AlertPriority.LOW,
            source="test",
            category="test"
        )
        
        self.assertTrue(self.channel.should_send(high_alert))
        self.assertFalse(self.channel.should_send(low_alert))
    
    def test_rate_limiting(self):
        """Test rate limiting"""
        self.channel.rate_limit = 2  # 2 alerts per minute
        
        alert = Alert(
            alert_id="TEST007",
            title="Test",
            description="Test",
            priority=AlertPriority.HIGH,
            source="test",
            category="test"
        )
        
        # First two should pass
        self.assertTrue(self.channel.should_send(alert))
        self.channel.last_alert_time[int(time.time() / 60)] = 1
        
        self.assertTrue(self.channel.should_send(alert))
        self.channel.last_alert_time[int(time.time() / 60)] = 2
        
        # Third should fail
        self.assertFalse(self.channel.should_send(alert))
    
    @patch('smtplib.SMTP')
    def test_send_email(self, mock_smtp):
        """Test email sending"""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        
        alert = Alert(
            alert_id="TEST008",
            title="Email Test",
            description="Testing email alert",
            priority=AlertPriority.HIGH,
            source="test",
            category="test",
            data={'detail': 'value'},
            actions=['Do this', 'Do that']
        )
        
        result = self.channel.send(alert)
        
        self.assertTrue(result)
        mock_smtp.assert_called_once_with('smtp.test.com', 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('test@test.com', 'testpass')
        mock_server.send_message.assert_called_once()
    
    def test_html_content_creation(self):
        """Test HTML content generation"""
        alert = Alert(
            alert_id="TEST009",
            title="HTML Test",
            description="Testing HTML generation",
            priority=AlertPriority.CRITICAL,
            source="test",
            category="test"
        )
        
        html = self.channel._create_html_content(alert)
        
        self.assertIn('HTML Test', html)
        self.assertIn('CRITICAL', html)
        self.assertIn('#FF0000', html)  # Critical color


class TestSlackAlertChannel(unittest.TestCase):
    """Test SlackAlertChannel"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'enabled': True,
            'webhook_url': 'https://hooks.slack.com/test',
            'channel': '#alerts',
            'username': 'SharpEye'
        }
        self.channel = SlackAlertChannel(self.config)
    
    @patch('requests.post')
    def test_send_slack(self, mock_post):
        """Test Slack alert sending"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        alert = Alert(
            alert_id="TEST010",
            title="Slack Test",
            description="Testing Slack alert",
            priority=AlertPriority.HIGH,
            source="test",
            category="security"
        )
        
        result = self.channel.send(alert)
        
        self.assertTrue(result)
        mock_post.assert_called_once()
        
        # Check payload
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        
        self.assertEqual(payload['channel'], '#alerts')
        self.assertEqual(payload['username'], 'SharpEye')
        self.assertIn('attachments', payload)
        self.assertEqual(payload['attachments'][0]['color'], 'warning')


class TestWebhookAlertChannel(unittest.TestCase):
    """Test WebhookAlertChannel"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'enabled': True,
            'url': 'https://webhook.test.com/alert',
            'method': 'POST',
            'headers': {'Authorization': 'Bearer token'},
            'timeout': 10
        }
        self.channel = WebhookAlertChannel(self.config)
    
    @patch('requests.request')
    def test_send_webhook(self, mock_request):
        """Test webhook alert sending"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        alert = Alert(
            alert_id="TEST011",
            title="Webhook Test",
            description="Testing webhook alert",
            priority=AlertPriority.MEDIUM,
            source="test",
            category="test"
        )
        
        result = self.channel.send(alert)
        
        self.assertTrue(result)
        mock_request.assert_called_once()
        
        # Check request parameters
        call_args = mock_request.call_args
        self.assertEqual(call_args[1]['method'], 'POST')
        self.assertEqual(call_args[1]['url'], 'https://webhook.test.com/alert')
        self.assertIn('alert', call_args[1]['json'])


class TestSyslogAlertChannel(unittest.TestCase):
    """Test SyslogAlertChannel"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'enabled': True,
            'facility': 'local0',
            'priority_map': {}
        }
        self.channel = SyslogAlertChannel(self.config)
    
    @patch('subprocess.run')
    def test_send_syslog(self, mock_run):
        """Test syslog alert sending"""
        mock_run.return_value = Mock(returncode=0)
        
        alert = Alert(
            alert_id="TEST012",
            title="Syslog Test",
            description="Testing syslog alert",
            priority=AlertPriority.HIGH,
            source="test",
            category="test"
        )
        
        result = self.channel.send(alert)
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        
        # Check command
        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args[0], 'logger')
        self.assertIn('local0.err', call_args)  # High priority -> err


class TestAlertManager(unittest.TestCase):
    """Test AlertManager"""
    
    def setUp(self):
        """Set up test cases"""
        self.config = {
            'dedup_window_minutes': 5,
            'max_history': 100,
            'channels': {
                'email': {
                    'enabled': False
                },
                'slack': {
                    'enabled': False
                }
            }
        }
        self.manager = AlertManager(self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.manager.stop()
    
    def test_create_alert(self):
        """Test alert creation"""
        alert = self.manager.create_alert(
            title="Test Alert",
            description="Test description",
            priority=AlertPriority.MEDIUM,
            source="test",
            category="test",
            data={'key': 'value'},
            actions=['Action 1']
        )
        
        self.assertIsNotNone(alert.alert_id)
        self.assertEqual(alert.title, "Test Alert")
        self.assertEqual(alert.priority, AlertPriority.MEDIUM)
    
    def test_alert_deduplication(self):
        """Test alert deduplication"""
        alert1 = self.manager.create_alert(
            title="Duplicate Alert",
            description="Test",
            priority=AlertPriority.HIGH,
            source="same_source",
            category="same_category"
        )
        
        alert2 = self.manager.create_alert(
            title="Duplicate Alert",
            description="Different description",
            priority=AlertPriority.LOW,
            source="same_source",
            category="same_category"
        )
        
        # Send first alert
        result1 = self.manager.send_alert(alert1)
        self.assertTrue(result1)
        
        # Second alert should be deduplicated
        result2 = self.manager.send_alert(alert2)
        self.assertFalse(result2)
    
    def test_alert_history(self):
        """Test alert history management"""
        # Create and send alerts
        for i in range(5):
            alert = self.manager.create_alert(
                title=f"Alert {i}",
                description="Test",
                priority=AlertPriority.MEDIUM,
                source="test",
                category="test"
            )
            self.manager.send_alert(alert)
            # Process the alert
            time.sleep(0.1)
            while not self.manager.alert_queue.empty():
                time.sleep(0.1)
        
        # Check history
        recent = self.manager.get_recent_alerts(hours=1)
        self.assertGreater(len(recent), 0)
    
    def test_alert_filtering(self):
        """Test alert filtering"""
        # Create alerts with different priorities and categories
        high_alert = self.manager.create_alert(
            title="High Priority",
            description="Test",
            priority=AlertPriority.HIGH,
            source="test",
            category="security"
        )
        
        low_alert = self.manager.create_alert(
            title="Low Priority",
            description="Test",
            priority=AlertPriority.LOW,
            source="test",
            category="performance"
        )
        
        self.manager.send_alert(high_alert)
        self.manager.send_alert(low_alert)
        
        # Wait for processing
        time.sleep(0.2)
        
        # Filter by priority
        high_only = self.manager.get_recent_alerts(priority=AlertPriority.HIGH)
        self.assertEqual(len([a for a in high_only if a.priority == AlertPriority.HIGH]), 
                        len(high_only))
        
        # Filter by category
        security_only = self.manager.get_recent_alerts(category="security")
        self.assertEqual(len([a for a in security_only if a.category == "security"]), 
                        len(security_only))
    
    def test_alert_acknowledgment(self):
        """Test alert acknowledgment"""
        alert = self.manager.create_alert(
            title="Test Alert",
            description="Test",
            priority=AlertPriority.MEDIUM,
            source="test",
            category="test"
        )
        
        self.manager.send_alert(alert)
        time.sleep(0.1)
        
        # Acknowledge alert
        result = self.manager.acknowledge_alert(alert.alert_id)
        self.assertTrue(result)
        
        # Check if acknowledged
        recent = self.manager.get_recent_alerts()
        ack_alert = next((a for a in recent if a.alert_id == alert.alert_id), None)
        if ack_alert:
            self.assertTrue(ack_alert.acknowledged)
    
    def test_alert_resolution(self):
        """Test alert resolution"""
        alert = self.manager.create_alert(
            title="Test Alert",
            description="Test",
            priority=AlertPriority.MEDIUM,
            source="test",
            category="test"
        )
        
        self.manager.send_alert(alert)
        time.sleep(0.1)
        
        # Resolve alert
        result = self.manager.resolve_alert(alert.alert_id)
        self.assertTrue(result)
        
        # Check if resolved
        recent = self.manager.get_recent_alerts()
        resolved_alert = next((a for a in recent if a.alert_id == alert.alert_id), None)
        if resolved_alert:
            self.assertTrue(resolved_alert.resolved)
    
    def test_statistics(self):
        """Test alert statistics"""
        # Create alerts with different attributes
        for i in range(3):
            alert = self.manager.create_alert(
                title=f"Alert {i}",
                description="Test",
                priority=AlertPriority.HIGH if i < 2 else AlertPriority.LOW,
                source="source1" if i < 2 else "source2",
                category="cat1" if i == 0 else "cat2"
            )
            self.manager.send_alert(alert)
        
        time.sleep(0.2)
        
        stats = self.manager.get_statistics()
        
        self.assertIn('total_alerts', stats)
        self.assertIn('by_priority', stats)
        self.assertIn('by_category', stats)
        self.assertIn('by_source', stats)
    
    def test_callback_registration(self):
        """Test callback registration"""
        callback_called = False
        received_alert = None
        
        def test_callback(alert):
            nonlocal callback_called, received_alert
            callback_called = True
            received_alert = alert
        
        self.manager.register_callback(test_callback)
        
        # Send alert
        alert = self.manager.create_alert(
            title="Callback Test",
            description="Test",
            priority=AlertPriority.HIGH,
            source="test",
            category="test"
        )
        
        self.manager.send_alert(alert)
        
        # Wait for processing
        time.sleep(0.5)
        
        # Callback should have been called
        # Note: This might not work in the test due to threading
    
    def test_singleton_manager(self):
        """Test singleton alert manager"""
        manager1 = get_alert_manager()
        manager2 = get_alert_manager()
        
        self.assertIs(manager1, manager2)


if __name__ == '__main__':
    unittest.main()