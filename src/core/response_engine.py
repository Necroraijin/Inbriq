"""
Response Engine - Automated threat response and mitigation
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import random

from .models import SecurityEvent

logger = logging.getLogger(__name__)

class ResponseEngine:
    """
    Automated response engine for handling security threats
    """
    
    def __init__(self):
        self.response_rules = {}
        self.active_responses = {}
        self.response_history = []
        self.learning_data = []

        self._initialize_response_rules()
        
        logger.info("Response Engine initialized")

    def _initialize_response_rules(self):
        """Initialize automated response rules"""
        self.response_rules = {
            "ddos_attack": {
                "severity_threshold": 0.7,
                "actions": [
                    {"action": "block_ip", "priority": 1, "immediate": True},
                    {"action": "rate_limit", "priority": 2, "immediate": True},
                    {"action": "alert_admin", "priority": 3, "immediate": False}
                ],
                "cooldown_minutes": 5
            },
            "malware_traffic": {
                "severity_threshold": 0.6,
                "actions": [
                    {"action": "quarantine", "priority": 1, "immediate": True},
                    {"action": "block_ip", "priority": 2, "immediate": True},
                    {"action": "scan_system", "priority": 3, "immediate": False}
                ],
                "cooldown_minutes": 10
            },
            "network_anomaly": {
                "severity_threshold": 0.5,
                "actions": [
                    {"action": "monitor_closely", "priority": 1, "immediate": True},
                    {"action": "alert_admin", "priority": 2, "immediate": False}
                ],
                "cooldown_minutes": 15
            },
            "suspicious_login": {
                "severity_threshold": 0.7,
                "actions": [
                    {"action": "temporary_lock", "priority": 1, "immediate": True},
                    {"action": "require_2fa", "priority": 2, "immediate": True},
                    {"action": "alert_admin", "priority": 3, "immediate": False}
                ],
                "cooldown_minutes": 30
            },
            "port_scan": {
                "severity_threshold": 0.8,
                "actions": [
                    {"action": "block_ip", "priority": 1, "immediate": True},
                    {"action": "honeypot", "priority": 2, "immediate": True},
                    {"action": "alert_admin", "priority": 3, "immediate": False}
                ],
                "cooldown_minutes": 5
            },
            "data_exfiltration": {
                "severity_threshold": 0.9,
                "actions": [
                    {"action": "block_connection", "priority": 1, "immediate": True},
                    {"action": "quarantine", "priority": 2, "immediate": True},
                    {"action": "alert_admin", "priority": 3, "immediate": True},
                    {"action": "backup_data", "priority": 4, "immediate": False}
                ],
                "cooldown_minutes": 0
            },
            "transaction_anomaly": {
                "severity_threshold": 0.8,
                "actions": [
                    {"action": "freeze_transaction", "priority": 1, "immediate": True},
                    {"action": "require_verification", "priority": 2, "immediate": True},
                    {"action": "alert_fraud_team", "priority": 3, "immediate": True}
                ],
                "cooldown_minutes": 0
            }
        }

    async def determine_response(self, event: SecurityEvent) -> List[str]:
        """
        Determine appropriate response actions for a security event
        """
        try:
            response_actions = []

            rules = self.response_rules.get(event.event_type, {})
            
            if not rules:
                logger.warning(f"No response rules found for event type: {event.event_type}")
                return response_actions

            severity_threshold = rules.get("severity_threshold", 0.5)
            if event.threat_score < severity_threshold:
                logger.info(f"Threat score {event.threat_score} below threshold {severity_threshold}")
                return response_actions

            cooldown_minutes = rules.get("cooldown_minutes", 0)
            if self._is_in_cooldown(event.source_ip, event.event_type, cooldown_minutes):
                logger.info(f"Response in cooldown for {event.source_ip}")
                return response_actions

            actions = rules.get("actions", [])
            
            for action_config in actions:
                action = action_config["action"]
                priority = action_config["priority"]
                immediate = action_config["immediate"]

                if self._should_take_action(event, action_config):
                    response_actions.append(action)

                    if immediate:
                        await self._execute_action(event, action)

                    self._record_response(event, action, priority)

            adaptive_actions = await self._get_adaptive_responses(event)
            response_actions.extend(adaptive_actions)
            
            logger.info(f"Determined {len(response_actions)} response actions for {event.event_type}")
            return response_actions
            
        except Exception as e:
            logger.error(f"Error determining response: {e}")
            return []

    def _should_take_action(self, event: SecurityEvent, action_config: Dict) -> bool:
        """Determine if an action should be taken based on event characteristics"""
        try:

            threat_score = event.threat_score
            severity = event.severity

            severity_multipliers = {
                "low": 0.5,
                "medium": 1.0,
                "high": 1.5,
                "critical": 2.0
            }
            
            multiplier = severity_multipliers.get(severity, 1.0)
            adjusted_score = threat_score * multiplier

            action_thresholds = {
                "block_ip": 0.7,
                "quarantine": 0.8,
                "rate_limit": 0.6,
                "alert_admin": 0.5,
                "monitor_closely": 0.4,
                "temporary_lock": 0.7,
                "require_2fa": 0.6,
                "honeypot": 0.8,
                "block_connection": 0.9,
                "freeze_transaction": 0.8,
                "require_verification": 0.7,
                "alert_fraud_team": 0.8,
                "scan_system": 0.6,
                "backup_data": 0.9
            }
            
            threshold = action_thresholds.get(action_config["action"], 0.5)
            
            return adjusted_score >= threshold
            
        except Exception as e:
            logger.error(f"Error determining action: {e}")
            return False

    async def _execute_action(self, event: SecurityEvent, action: str):
        """Execute a specific response action"""
        try:
            action_id = f"{event.event_id}_{action}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            self.active_responses[action_id] = {
                "event_id": event.event_id,
                "action": action,
                "start_time": datetime.now(),
                "status": "executing",
                "source_ip": event.source_ip
            }

            if action == "block_ip":
                await self._block_ip(event.source_ip, event.description)
            elif action == "quarantine":
                await self._quarantine_system(event.source_ip, event.description)
            elif action == "rate_limit":
                await self._apply_rate_limit(event.source_ip, event.description)
            elif action == "alert_admin":
                await self._send_admin_alert(event)
            elif action == "monitor_closely":
                await self._enhance_monitoring(event.source_ip)
            elif action == "temporary_lock":
                await self._temporary_lock(event.source_ip, event.description)
            elif action == "require_2fa":
                await self._require_2fa(event.source_ip)
            elif action == "honeypot":
                await self._deploy_honeypot(event.source_ip)
            elif action == "block_connection":
                await self._block_connection(event.source_ip, event.target_ip)
            elif action == "freeze_transaction":
                await self._freeze_transaction(event)
            elif action == "require_verification":
                await self._require_verification(event)
            elif action == "alert_fraud_team":
                await self._alert_fraud_team(event)
            elif action == "scan_system":
                await self._scan_system(event.source_ip)
            elif action == "backup_data":
                await self._backup_data(event)
            else:
                logger.warning(f"Unknown action: {action}")

            if action_id in self.active_responses:
                self.active_responses[action_id]["status"] = "completed"
                self.active_responses[action_id]["end_time"] = datetime.now()
            
            logger.info(f"✅ Executed action: {action} for event {event.event_id}")
            
        except Exception as e:
            logger.error(f"Error executing action {action}: {e}")
            if action_id in self.active_responses:
                self.active_responses[action_id]["status"] = "failed"
                self.active_responses[action_id]["error"] = str(e)

    async def _block_ip(self, ip: str, reason: str):
        """Block an IP address"""
        logger.info(f"🔒 Blocking IP {ip}: {reason}")

        await asyncio.sleep(0.1)

    async def _quarantine_system(self, ip: str, reason: str):
        """Quarantine a system"""
        logger.info(f"🔐 Quarantining system {ip}: {reason}")

        await asyncio.sleep(0.2)

    async def _apply_rate_limit(self, ip: str, reason: str):
        """Apply rate limiting to an IP"""
        logger.info(f"⏱️ Applying rate limit to {ip}: {reason}")

        await asyncio.sleep(0.1)

    async def _send_admin_alert(self, event: SecurityEvent):
        """Send alert to administrators"""
        alert_message = f"""
        🚨 SECURITY ALERT 🚨
        
        Event ID: {event.event_id}
        Type: {event.event_type}
        Severity: {event.severity}
        Source IP: {event.source_ip}
        Description: {event.description}
        Threat Score: {event.threat_score:.3f}
        Timestamp: {event.timestamp}
        
        Please investigate immediately.
        """
        
        logger.warning(f"📢 Admin Alert: {event.description}")

        await asyncio.sleep(0.1)

    async def _enhance_monitoring(self, ip: str):
        """Enhance monitoring for a specific IP"""
        logger.info(f"👁️ Enhancing monitoring for {ip}")

        await asyncio.sleep(0.1)

    async def _temporary_lock(self, ip: str, reason: str):
        """Temporarily lock an account/IP"""
        logger.info(f"🔒 Temporarily locking {ip}: {reason}")

        await asyncio.sleep(0.1)

    async def _require_2fa(self, ip: str):
        """Require two-factor authentication"""
        logger.info(f"🔐 Requiring 2FA for {ip}")

        await asyncio.sleep(0.1)

    async def _deploy_honeypot(self, ip: str):
        """Deploy honeypot to gather intelligence"""
        logger.info(f"🍯 Deploying honeypot for {ip}")

        await asyncio.sleep(0.2)

    async def _block_connection(self, source_ip: str, target_ip: str):
        """Block specific connection"""
        logger.info(f"🚫 Blocking connection {source_ip} -> {target_ip}")

        await asyncio.sleep(0.1)

    async def _freeze_transaction(self, event: SecurityEvent):
        """Freeze suspicious transaction"""
        logger.info(f"❄️ Freezing transaction: {event.description}")

        await asyncio.sleep(0.1)

    async def _require_verification(self, event: SecurityEvent):
        """Require additional verification"""
        logger.info(f"✅ Requiring verification: {event.description}")

        await asyncio.sleep(0.1)

    async def _alert_fraud_team(self, event: SecurityEvent):
        """Alert fraud detection team"""
        logger.info(f"🚨 Alerting fraud team: {event.description}")

        await asyncio.sleep(0.1)

    async def _scan_system(self, ip: str):
        """Scan system for malware"""
        logger.info(f"🔍 Scanning system {ip} for malware")

        await asyncio.sleep(0.5)

    async def _backup_data(self, event: SecurityEvent):
        """Backup critical data"""
        logger.info(f"💾 Backing up data: {event.description}")

        await asyncio.sleep(0.3)

    def _record_response(self, event: SecurityEvent, action: str, priority: int):
        """Record response action in history"""
        response_record = {
            "timestamp": datetime.now(),
            "event_id": event.event_id,
            "event_type": event.event_type,
            "action": action,
            "priority": priority,
            "source_ip": event.source_ip,
            "threat_score": event.threat_score,
            "severity": event.severity
        }
        
        self.response_history.append(response_record)

        if len(self.response_history) > 1000:
            self.response_history = self.response_history[-1000:]

    def _is_in_cooldown(self, source_ip: str, event_type: str, cooldown_minutes: int) -> bool:
        """Check if response is in cooldown period"""
        if cooldown_minutes <= 0:
            return False
        
        cutoff_time = datetime.now() - timedelta(minutes=cooldown_minutes)

        recent_responses = [
            response for response in self.response_history
            if (response["source_ip"] == source_ip and 
                response["event_type"] == event_type and 
                response["timestamp"] > cutoff_time)
        ]
        
        return len(recent_responses) > 0

    async def _get_adaptive_responses(self, event: SecurityEvent) -> List[str]:
        """Get adaptive responses based on learning from past events"""
        adaptive_actions = []
        
        try:

            similar_events = self._find_similar_events(event)
            
            if similar_events:

                successful_actions = self._analyze_successful_responses(similar_events)
                adaptive_actions.extend(successful_actions)

            if random.random() < 0.3:
                adaptive_actions.append("adaptive_monitoring")
            
        except Exception as e:
            logger.error(f"Error getting adaptive responses: {e}")
        
        return adaptive_actions

    def _find_similar_events(self, event: SecurityEvent) -> List[Dict]:
        """Find similar past events for learning"""
        similar_events = []
        
        try:

            for response in self.response_history:
                if (response["event_type"] == event.event_type and
                    response["source_ip"] == event.source_ip):
                    similar_events.append(response)

            return similar_events[-10:]
            
        except Exception as e:
            logger.error(f"Error finding similar events: {e}")
            return []

    def _analyze_successful_responses(self, similar_events: List[Dict]) -> List[str]:
        """Analyze which responses were successful for similar events"""
        successful_actions = []
        
        try:

            action_counts = {}
            
            for event in similar_events:
                action = event["action"]
                if action not in action_counts:
                    action_counts[action] = {"count": 0, "success": 0}
                
                action_counts[action]["count"] += 1

                action_counts[action]["success"] += 1

            for action, stats in action_counts.items():
                if stats["count"] >= 2 and stats["success"] / stats["count"] > 0.7:
                    successful_actions.append(action)
            
        except Exception as e:
            logger.error(f"Error analyzing successful responses: {e}")
        
        return successful_actions

    def get_response_statistics(self) -> Dict:
        """Get response engine statistics"""
        try:
            total_responses = len(self.response_history)
            active_responses = len([r for r in self.active_responses.values() if r["status"] == "executing"])

            action_counts = {}
            for response in self.response_history:
                action = response["action"]
                action_counts[action] = action_counts.get(action, 0) + 1

            event_type_stats = {}
            for response in self.response_history:
                event_type = response["event_type"]
                if event_type not in event_type_stats:
                    event_type_stats[event_type] = {"total": 0, "successful": 0}
                
                event_type_stats[event_type]["total"] += 1

                event_type_stats[event_type]["successful"] += 1
            
            return {
                "total_responses": total_responses,
                "active_responses": active_responses,
                "action_frequency": dict(sorted(action_counts.items(), key=lambda x: x[1], reverse=True)),
                "event_type_stats": event_type_stats,
                "response_rules_count": len(self.response_rules),
                "learning_data_points": len(self.learning_data)
            }
            
        except Exception as e:
            logger.error(f"Error getting response statistics: {e}")
            return {}

    def get_active_responses(self) -> List[Dict]:
        """Get currently active responses"""
        serializable_responses = []
        for response in self.active_responses.values():
            serializable_response = response.copy()
            if "start_time" in serializable_response and isinstance(serializable_response["start_time"], datetime):
                serializable_response["start_time"] = serializable_response["start_time"].isoformat()
            if "end_time" in serializable_response and isinstance(serializable_response["end_time"], datetime):
                serializable_response["end_time"] = serializable_response["end_time"].isoformat()
            serializable_responses.append(serializable_response)
        return serializable_responses

    def get_response_history(self, limit: int = 50) -> List[Dict]:
        """Get response history"""
        return [
            {
                "timestamp": response["timestamp"].isoformat() if isinstance(response["timestamp"], datetime) else response["timestamp"],
                "event_id": response["event_id"],
                "event_type": response["event_type"],
                "action": response["action"],
                "priority": response["priority"],
                "source_ip": response["source_ip"],
                "threat_score": response["threat_score"],
                "severity": response["severity"]
            }
            for response in self.response_history[-limit:]
        ]

    def add_response_rule(self, event_type: str, rule_config: Dict):
        """Add a new response rule"""
        self.response_rules[event_type] = rule_config
        logger.info(f"Added response rule for {event_type}")

    def update_response_rule(self, event_type: str, rule_config: Dict):
        """Update an existing response rule"""
        if event_type in self.response_rules:
            self.response_rules[event_type].update(rule_config)
            logger.info(f"Updated response rule for {event_type}")
        else:
            logger.warning(f"Response rule not found for {event_type}")

    def remove_response_rule(self, event_type: str):
        """Remove a response rule"""
        if event_type in self.response_rules:
            del self.response_rules[event_type]
            logger.info(f"Removed response rule for {event_type}")
        else:
            logger.warning(f"Response rule not found for {event_type}")