"""
Threat Detection Agent - Specialized in identifying and analyzing threats
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any
import random
import numpy as np

from .base_agent import BaseAgent, AgentCapability

logger = logging.getLogger(__name__)

class ThreatDetectionAgent(BaseAgent):
    """
    Specialized agent for threat detection and analysis
    """
    
    def __init__(self, agent_id: str = "threat_detector_001"):
        super().__init__(agent_id, "Threat Detection Specialist", "threat_detection")

        self.capabilities = [
            AgentCapability(
                capability_name="network_anomaly_detection",
                description="Detect anomalies in network traffic patterns",
                input_types=["network_traffic", "packet_data"],
                output_types=["anomaly_score", "threat_indicators"]
            ),
            AgentCapability(
                capability_name="malware_analysis",
                description="Analyze and identify malware signatures",
                input_types=["file_hash", "behavioral_data"],
                output_types=["malware_type", "confidence_score"]
            ),
            AgentCapability(
                capability_name="ddos_detection",
                description="Detect distributed denial of service attacks",
                input_types=["traffic_volume", "connection_patterns"],
                output_types=["ddos_probability", "attack_type"]
            ),
            AgentCapability(
                capability_name="intrusion_detection",
                description="Detect unauthorized access attempts",
                input_types=["login_attempts", "access_logs"],
                output_types=["intrusion_probability", "attack_vector"]
            )
        ]
        
        self.specializations = [
            "network_security",
            "malware_analysis",
            "intrusion_detection",
            "anomaly_detection"
        ]

        self.threat_models = {
            "ddos": {"threshold": 0.8, "accuracy": 0.95},
            "malware": {"threshold": 0.7, "accuracy": 0.92},
            "intrusion": {"threshold": 0.75, "accuracy": 0.88},
            "anomaly": {"threshold": 0.6, "accuracy": 0.85}
        }

        self.detection_history = []
        self.false_positive_rate = 0.05
        self.false_negative_rate = 0.03
        
        logger.info(f"🔍 Threat Detection Agent {self.agent_id} initialized")

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat detection tasks"""
        task_type = task_data.get("task_type", "unknown")
        
        if task_type == "network_analysis":
            return await self._analyze_network_traffic(task_data)
        elif task_type == "malware_scan":
            return await self._scan_for_malware(task_data)
        elif task_type == "ddos_detection":
            return await self._detect_ddos(task_data)
        elif task_type == "intrusion_analysis":
            return await self._analyze_intrusion_attempts(task_data)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat data and provide detailed assessment"""
        threat_type = threat_data.get("type", "unknown")
        severity = threat_data.get("severity", "medium")

        analysis_result = {
            "threat_id": f"threat_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "threat_type": threat_type,
            "severity": severity,
            "confidence_score": self._calculate_confidence(threat_data),
            "attack_vector": self._identify_attack_vector(threat_data),
            "indicators_of_compromise": self._extract_iocs(threat_data),
            "recommended_actions": self._recommend_actions(threat_type, severity),
            "risk_assessment": self._assess_risk(threat_data),
            "analysis_timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id
        }

        await self._learn_from_analysis(threat_data, analysis_result)
        
        return analysis_result

    async def _analyze_network_traffic(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network traffic for threats"""
        traffic_data = task_data.get("traffic_data", {})

        packet_count = traffic_data.get("packet_count", 0)
        unique_ips = traffic_data.get("unique_ips", 0)
        protocol_distribution = traffic_data.get("protocols", {})

        anomaly_score = self._calculate_network_anomaly_score(traffic_data)
        
        result = {
            "analysis_type": "network_traffic",
            "anomaly_score": anomaly_score,
            "threat_indicators": self._identify_network_threats(traffic_data),
            "traffic_patterns": self._analyze_traffic_patterns(traffic_data),
            "recommendations": self._get_network_recommendations(anomaly_score),
            "confidence": 0.85 + random.uniform(-0.1, 0.1)
        }
        
        return result

    async def _scan_for_malware(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for malware signatures and behaviors"""
        scan_data = task_data.get("scan_data", {})

        file_hashes = scan_data.get("file_hashes", [])
        behavioral_data = scan_data.get("behavioral_data", {})
        
        malware_detections = []
        for file_hash in file_hashes:
            if self._is_malicious_hash(file_hash):
                malware_detections.append({
                    "file_hash": file_hash,
                    "malware_type": self._classify_malware(file_hash),
                    "confidence": random.uniform(0.8, 0.98)
                })
        
        result = {
            "analysis_type": "malware_scan",
            "files_scanned": len(file_hashes),
            "malware_detected": len(malware_detections),
            "detections": malware_detections,
            "behavioral_analysis": self._analyze_behavioral_patterns(behavioral_data),
            "scan_confidence": 0.92 + random.uniform(-0.05, 0.05)
        }
        
        return result

    async def _detect_ddos(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect DDoS attacks"""
        traffic_data = task_data.get("traffic_data", {})

        packet_rate = traffic_data.get("packet_rate", 0)
        connection_rate = traffic_data.get("connection_rate", 0)
        source_diversity = traffic_data.get("source_diversity", 0)
        
        ddos_probability = self._calculate_ddos_probability(traffic_data)
        
        result = {
            "analysis_type": "ddos_detection",
            "ddos_probability": ddos_probability,
            "attack_type": self._classify_ddos_attack(traffic_data),
            "traffic_anomalies": self._identify_traffic_anomalies(traffic_data),
            "source_analysis": self._analyze_attack_sources(traffic_data),
            "mitigation_recommendations": self._get_ddos_mitigation_recommendations(ddos_probability),
            "confidence": 0.95 + random.uniform(-0.03, 0.03)
        }
        
        return result

    async def _analyze_intrusion_attempts(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze intrusion attempts"""
        access_data = task_data.get("access_data", {})

        failed_logins = access_data.get("failed_logins", 0)
        successful_logins = access_data.get("successful_logins", 0)
        access_patterns = access_data.get("access_patterns", {})
        
        intrusion_probability = self._calculate_intrusion_probability(access_data)
        
        result = {
            "analysis_type": "intrusion_analysis",
            "intrusion_probability": intrusion_probability,
            "attack_vectors": self._identify_attack_vectors(access_data),
            "compromised_accounts": self._identify_compromised_accounts(access_data),
            "timeline_analysis": self._analyze_attack_timeline(access_data),
            "recommended_responses": self._get_intrusion_responses(intrusion_probability),
            "confidence": 0.88 + random.uniform(-0.05, 0.05)
        }
        
        return result

    def _calculate_confidence(self, threat_data: Dict[str, Any]) -> float:
        """Calculate confidence score for threat analysis"""
        base_confidence = 0.8

        data_quality = threat_data.get("data_quality", 0.5)
        threat_severity = threat_data.get("severity", "medium")
        
        severity_multiplier = {
            "low": 0.7,
            "medium": 0.8,
            "high": 0.9,
            "critical": 0.95
        }.get(threat_severity, 0.8)
        
        confidence = base_confidence * data_quality * severity_multiplier
        return min(1.0, confidence + random.uniform(-0.1, 0.1))

    def _identify_attack_vector(self, threat_data: Dict[str, Any]) -> str:
        """Identify the attack vector"""
        vectors = [
            "network_infiltration",
            "email_phishing",
            "web_application_attack",
            "insider_threat",
            "supply_chain_attack",
            "social_engineering"
        ]
        return random.choice(vectors)

    def _extract_iocs(self, threat_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators of compromise"""
        iocs = []

        if "source_ip" in threat_data:
            iocs.append({
                "type": "ip_address",
                "value": threat_data["source_ip"],
                "confidence": random.uniform(0.7, 0.95)
            })
        
        if "file_hash" in threat_data:
            iocs.append({
                "type": "file_hash",
                "value": threat_data["file_hash"],
                "confidence": random.uniform(0.8, 0.98)
            })
        
        return iocs

    def _recommend_actions(self, threat_type: str, severity: str) -> List[str]:
        """Recommend actions based on threat type and severity"""
        actions = []
        
        if severity in ["high", "critical"]:
            actions.extend([
                "immediate_containment",
                "isolate_affected_systems",
                "notify_security_team",
                "activate_incident_response"
            ])
        
        if threat_type == "ddos":
            actions.extend(["enable_ddos_protection", "rate_limiting"])
        elif threat_type == "malware":
            actions.extend(["quarantine_files", "scan_systems"])
        elif threat_type == "intrusion":
            actions.extend(["block_suspicious_ips", "reset_credentials"])
        
        return actions

    def _assess_risk(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the risk level of the threat"""
        return {
            "risk_level": random.choice(["low", "medium", "high", "critical"]),
            "business_impact": random.choice(["minimal", "moderate", "significant", "severe"]),
            "likelihood": random.uniform(0.1, 0.9),
            "potential_damage": random.choice(["data_loss", "service_disruption", "reputation_damage", "financial_loss"])
        }

    async def _learn_from_analysis(self, threat_data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Learn from threat analysis to improve future detection"""
        if not self.learning_enabled:
            return

        threat_type = threat_data.get("type", "unknown")
        if threat_type in self.threat_models:

            self.threat_models[threat_type]["accuracy"] += 0.001
            self.threat_models[threat_type]["accuracy"] = min(1.0, self.threat_models[threat_type]["accuracy"])

        self.detection_history.append({
            "timestamp": datetime.now(),
            "threat_data": threat_data,
            "analysis_result": analysis_result
        })

        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-1000:]

    def _calculate_network_anomaly_score(self, traffic_data: Dict[str, Any]) -> float:
        """Calculate network anomaly score"""

        base_score = 0.3

        packet_rate = traffic_data.get("packet_rate", 0)
        if packet_rate > 1000:
            base_score += 0.3
        
        unique_ips = traffic_data.get("unique_ips", 0)
        if unique_ips > 100:
            base_score += 0.2
        
        return min(1.0, base_score + random.uniform(-0.1, 0.1))

    def _identify_network_threats(self, traffic_data: Dict[str, Any]) -> List[str]:
        """Identify specific network threats"""
        threats = []
        
        if traffic_data.get("packet_rate", 0) > 1000:
            threats.append("high_volume_attack")
        
        if traffic_data.get("unique_ips", 0) > 100:
            threats.append("distributed_attack")
        
        if traffic_data.get("port_scanning", False):
            threats.append("reconnaissance")
        
        return threats

    def _analyze_traffic_patterns(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze traffic patterns"""
        return {
            "peak_hours": [9, 14, 18],
            "traffic_distribution": "normal",
            "unusual_patterns": random.choice([True, False]),
            "geographic_distribution": "global"
        }

    def _get_network_recommendations(self, anomaly_score: float) -> List[str]:
        """Get network security recommendations"""
        recommendations = []
        
        if anomaly_score > 0.7:
            recommendations.extend([
                "increase_monitoring",
                "implement_rate_limiting",
                "review_firewall_rules"
            ])
        elif anomaly_score > 0.4:
            recommendations.extend([
                "monitor_closely",
                "check_logs"
            ])
        
        return recommendations

    def _is_malicious_hash(self, file_hash: str) -> bool:
        """Check if file hash is malicious (simplified)"""

        malicious_hashes = ["abc123", "def456", "ghi789"]
        return file_hash in malicious_hashes or random.random() < 0.1

    def _classify_malware(self, file_hash: str) -> str:
        """Classify malware type"""
        types = ["trojan", "ransomware", "spyware", "adware", "rootkit"]
        return random.choice(types)

    def _analyze_behavioral_patterns(self, behavioral_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral patterns for malware"""
        return {
            "suspicious_activities": random.randint(0, 5),
            "network_connections": random.randint(0, 20),
            "file_modifications": random.randint(0, 10),
            "registry_changes": random.randint(0, 8)
        }

    def _calculate_ddos_probability(self, traffic_data: Dict[str, Any]) -> float:
        """Calculate DDoS attack probability"""
        base_prob = 0.2
        
        packet_rate = traffic_data.get("packet_rate", 0)
        if packet_rate > 5000:
            base_prob += 0.4
        
        connection_rate = traffic_data.get("connection_rate", 0)
        if connection_rate > 1000:
            base_prob += 0.3
        
        return min(1.0, base_prob + random.uniform(-0.1, 0.1))

    def _classify_ddos_attack(self, traffic_data: Dict[str, Any]) -> str:
        """Classify DDoS attack type"""
        types = ["volumetric", "protocol", "application_layer", "amplification"]
        return random.choice(types)

    def _identify_traffic_anomalies(self, traffic_data: Dict[str, Any]) -> List[str]:
        """Identify traffic anomalies"""
        anomalies = []
        
        if traffic_data.get("packet_rate", 0) > 1000:
            anomalies.append("unusual_packet_rate")
        
        if traffic_data.get("connection_rate", 0) > 500:
            anomalies.append("high_connection_rate")
        
        return anomalies

    def _analyze_attack_sources(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack sources"""
        return {
            "source_countries": random.randint(5, 50),
            "botnet_indicators": random.choice([True, False]),
            "source_diversity": random.uniform(0.3, 0.9)
        }

    def _get_ddos_mitigation_recommendations(self, ddos_probability: float) -> List[str]:
        """Get DDoS mitigation recommendations"""
        recommendations = []
        
        if ddos_probability > 0.8:
            recommendations.extend([
                "activate_ddos_protection",
                "implement_rate_limiting",
                "contact_isp",
                "deploy_mitigation_services"
            ])
        elif ddos_probability > 0.5:
            recommendations.extend([
                "monitor_traffic",
                "prepare_mitigation",
                "check_capacity"
            ])
        
        return recommendations

    def _calculate_intrusion_probability(self, access_data: Dict[str, Any]) -> float:
        """Calculate intrusion probability"""
        base_prob = 0.1
        
        failed_logins = access_data.get("failed_logins", 0)
        if failed_logins > 10:
            base_prob += 0.4
        
        if access_data.get("unusual_access_patterns", False):
            base_prob += 0.3
        
        return min(1.0, base_prob + random.uniform(-0.1, 0.1))

    def _identify_attack_vectors(self, access_data: Dict[str, Any]) -> List[str]:
        """Identify attack vectors"""
        vectors = []
        
        if access_data.get("brute_force_attempts", False):
            vectors.append("brute_force")
        
        if access_data.get("privilege_escalation", False):
            vectors.append("privilege_escalation")
        
        if access_data.get("lateral_movement", False):
            vectors.append("lateral_movement")
        
        return vectors

    def _identify_compromised_accounts(self, access_data: Dict[str, Any]) -> List[str]:
        """Identify potentially compromised accounts"""

        compromised = []
        if random.random() < 0.2:
            compromised.append(f"user_{random.randint(1, 100)}")
        
        return compromised

    def _analyze_attack_timeline(self, access_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack timeline"""
        return {
            "first_attempt": "2025-10-02T02:00:00Z",
            "last_attempt": "2025-10-02T02:30:00Z",
            "attack_duration": "30 minutes",
            "peak_activity": "2025-10-02T02:15:00Z"
        }

    def _get_intrusion_responses(self, intrusion_probability: float) -> List[str]:
        """Get intrusion response recommendations"""
        responses = []
        
        if intrusion_probability > 0.7:
            responses.extend([
                "immediate_containment",
                "isolate_affected_systems",
                "reset_credentials",
                "activate_incident_response"
            ])
        elif intrusion_probability > 0.4:
            responses.extend([
                "increase_monitoring",
                "review_access_logs",
                "check_system_integrity"
            ])
        
        return responses

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics"""
        return {
            "total_detections": len(self.detection_history),
            "threat_models": self.threat_models,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "average_confidence": np.mean([d["analysis_result"]["confidence_score"] for d in self.detection_history[-100:]]) if self.detection_history else 0.0
        }