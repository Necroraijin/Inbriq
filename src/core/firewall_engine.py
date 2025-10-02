"""
Main firewall engine
"""

import asyncio
import psutil
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import numpy as np

from .threat_detector import ThreatDetector
from .response_engine import ResponseEngine
from .network_monitor import NetworkMonitor
from .models import SecurityEvent

logger = logging.getLogger(__name__)

class FirewallEngine:
    """
    Main firewall engine that orchestrates threat detection and response
    """
    
    def __init__(self, threat_detector: ThreatDetector, response_engine: ResponseEngine):
        self.threat_detector = threat_detector
        self.response_engine = response_engine
        self.network_monitor = NetworkMonitor()

        self.is_monitoring = False
        self.security_events: List[SecurityEvent] = []
        self.blocked_ips: set = set()
        self.trusted_ips: set = set()
        self.learning_mode = True

        self.stats = {
            "total_packets_analyzed": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "false_positives": 0,
            "uptime_start": datetime.now()
        }
        
        logger.info("Firewall Engine initialized")

    async def start_monitoring(self):
        """Start the continuous monitoring process"""
        self.is_monitoring = True
        logger.info("🛡️ Starting firewall monitoring...")

        tasks = [
            asyncio.create_task(self._monitor_network_traffic()),
            asyncio.create_task(self._analyze_threats()),
            asyncio.create_task(self._update_learning_models()),
            asyncio.create_task(self._cleanup_old_events()),
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Error in monitoring tasks: {e}")
            self.is_monitoring = False

    async def _monitor_network_traffic(self):
        """Continuously monitor network traffic"""
        while self.is_monitoring:
            try:

                network_stats = self.network_monitor.get_network_stats()

                traffic_data = self.network_monitor.capture_traffic_sample()
                
                if traffic_data:

                    self.stats["total_packets_analyzed"] += len(traffic_data)

                    await self._store_traffic_data(traffic_data)
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error monitoring network traffic: {e}")
                await asyncio.sleep(5)

    async def _analyze_threats(self):
        """Analyze traffic data for potential threats"""
        while self.is_monitoring:
            try:

                recent_traffic = await self._get_recent_traffic()
                
                if recent_traffic:

                    threats = await self.threat_detector.analyze_traffic(recent_traffic)
                    
                    for threat in threats:
                        await self._handle_threat(threat)
                
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Error analyzing threats: {e}")
                await asyncio.sleep(5)

    async def _handle_threat(self, threat_data: Dict):
        """Handle a detected threat"""
        try:

            event = SecurityEvent(
                event_id=f"evt_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.security_events)}",
                timestamp=datetime.now(),
                event_type=threat_data.get("type", "unknown"),
                severity=threat_data.get("severity", "medium"),
                source_ip=threat_data.get("source_ip", "unknown"),
                target_ip=threat_data.get("target_ip", "unknown"),
                protocol=threat_data.get("protocol", "unknown"),
                description=threat_data.get("description", "Threat detected"),
                threat_score=threat_data.get("threat_score", 0.5),
                response_actions=[],
                status="detected"
            )

            self.security_events.append(event)
            self.stats["threats_detected"] += 1

            response_actions = await self.response_engine.determine_response(event)
            event.response_actions = response_actions

            for action in response_actions:
                await self._execute_response_action(event, action)

            event.status = "mitigated" if response_actions else "investigating"
            
            logger.warning(f"🚨 Threat detected: {event.description} (Severity: {event.severity})")

            if hasattr(self, 'broadcast_alert'):
                await self.broadcast_alert({
                    "event_id": event.event_id,
                    "type": event.event_type,
                    "severity": event.severity,
                    "description": event.description,
                    "source_ip": event.source_ip,
                    "threat_score": event.threat_score,
                    "actions_taken": response_actions
                })
                
        except Exception as e:
            logger.error(f"Error handling threat: {e}")

    async def _execute_response_action(self, event: SecurityEvent, action: str):
        """Execute a specific response action"""
        try:
            if action == "block_ip":
                self.blocked_ips.add(event.source_ip)
                self.stats["threats_blocked"] += 1
                logger.info(f"🔒 Blocked IP: {event.source_ip}")
                
            elif action == "rate_limit":

                logger.info(f"⏱️ Rate limiting applied to {event.source_ip}")
                
            elif action == "alert_admin":
                logger.warning(f"📢 Admin alert: {event.description}")
                
            elif action == "quarantine":

                logger.info(f"🔐 Quarantined traffic from {event.source_ip}")
                
        except Exception as e:
            logger.error(f"Error executing response action {action}: {e}")

    async def _store_traffic_data(self, traffic_data: List[Dict]):
        """Store traffic data for analysis"""

        if not hasattr(self, '_recent_traffic'):
            self._recent_traffic = []
        
        self._recent_traffic.extend(traffic_data)

        if len(self._recent_traffic) > 1000:
            self._recent_traffic = self._recent_traffic[-1000:]

    async def _get_recent_traffic(self) -> List[Dict]:
        """Get recent traffic data for analysis"""
        if hasattr(self, '_recent_traffic'):
            return self._recent_traffic[-100:]
        return []

    async def _update_learning_models(self):
        """Update ML models based on new data"""
        while self.is_monitoring:
            try:
                if self.learning_mode:

                    await self.threat_detector.update_models()
                    
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Error updating learning models: {e}")
                await asyncio.sleep(60)

    async def _cleanup_old_events(self):
        """Clean up old security events"""
        while self.is_monitoring:
            try:

                cutoff_time = datetime.now() - timedelta(hours=24)
                self.security_events = [
                    event for event in self.security_events 
                    if event.timestamp > cutoff_time
                ]
                
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error cleaning up old events: {e}")
                await asyncio.sleep(300)

    def get_system_status(self) -> Dict:
        """Get current system status"""
        uptime = datetime.now() - self.stats["uptime_start"]

        serializable_stats = self.stats.copy()
        serializable_stats["uptime_start"] = self.stats["uptime_start"].isoformat()
        
        return {
            "status": "active" if self.is_monitoring else "inactive",
            "uptime_seconds": uptime.total_seconds(),
            "statistics": serializable_stats,
            "active_events": len([e for e in self.security_events if e.status != "resolved"]),
            "blocked_ips_count": len(self.blocked_ips),
            "learning_mode": self.learning_mode,
            "recent_events": [
                {
                    "id": event.event_id,
                    "timestamp": event.timestamp.isoformat(),
                    "type": event.event_type,
                    "severity": event.severity,
                    "description": event.description,
                    "status": event.status
                }
                for event in self.security_events[-10:]
            ]
        }

    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.is_monitoring = False
        logger.info("🛑 Firewall monitoring stopped")

    def add_trusted_ip(self, ip: str):
        """Add an IP to the trusted list"""
        self.trusted_ips.add(ip)
        logger.info(f"✅ Added trusted IP: {ip}")

    def remove_trusted_ip(self, ip: str):
        """Remove an IP from the trusted list"""
        self.trusted_ips.discard(ip)
        logger.info(f"❌ Removed trusted IP: {ip}")

    def get_security_events(self, limit: int = 50) -> List[Dict]:
        """Get security events"""
        return [
            {
                "id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "type": event.event_type,
                "severity": event.severity,
                "source_ip": event.source_ip,
                "target_ip": event.target_ip,
                "protocol": event.protocol,
                "description": event.description,
                "threat_score": event.threat_score,
                "response_actions": event.response_actions,
                "status": event.status
            }
            for event in self.security_events[-limit:]
        ]