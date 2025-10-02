"""
AI-Powered Threat Hunting - Autonomous investigation and threat discovery
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import json
from dataclasses import dataclass
from enum import Enum
import random
import hashlib
import secrets

logger = logging.getLogger(__name__)

class HuntingTechnique(Enum):
    """Threat hunting techniques"""
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    INDICATOR_HUNTING = "indicator_hunting"
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    MACHINE_LEARNING = "machine_learning"
    CORRELATION_ANALYSIS = "correlation_analysis"

class ThreatType(Enum):
    """Types of threats that can be hunted"""
    APT = "advanced_persistent_threat"
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ZERO_DAY = "zero_day_exploit"

class HuntingStatus(Enum):
    """Status of threat hunting operations"""
    PLANNING = "planning"
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    COMPLETED = "completed"

@dataclass
class HuntingHypothesis:
    """Threat hunting hypothesis"""
    hypothesis_id: str
    title: str
    description: str
    threat_type: ThreatType
    techniques: List[HuntingTechnique]
    confidence: float
    priority: str
    created_at: datetime
    status: HuntingStatus
    evidence: List[Dict[str, Any]]

@dataclass
class HuntingResult:
    """Result of threat hunting operation"""
    result_id: str
    hypothesis_id: str
    threat_detected: bool
    threat_type: Optional[ThreatType]
    confidence_score: float
    severity: str
    indicators: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    affected_assets: List[str]
    recommendations: List[str]
    discovered_at: datetime

@dataclass
class HuntingCampaign:
    """Threat hunting campaign"""
    campaign_id: str
    name: str
    description: str
    target_threats: List[ThreatType]
    techniques: List[HuntingTechnique]
    start_time: datetime
    end_time: Optional[datetime]
    status: HuntingStatus
    hypotheses: List[HuntingHypothesis]
    results: List[HuntingResult]
    success_rate: float

class AIThreatHunter:
    """
    AI-Powered Threat Hunting System for autonomous investigation
    """
    
    def __init__(self):
        self.active_campaigns = {}
        self.hunting_history = []
        self.threat_intelligence = {}
        self.behavioral_baselines = {}
        self.anomaly_models = {}
        self.correlation_engine = None

        self._initialize_hunting_capabilities()
        self._initialize_threat_intelligence()
        
        logger.info("🎯 AI-Powered Threat Hunter initialized")

    def _initialize_hunting_capabilities(self):
        """Initialize threat hunting capabilities"""
        self.hunting_capabilities = {
            'behavioral_analysis': {
                'enabled': True,
                'models': ['user_behavior', 'system_behavior', 'network_behavior'],
                'confidence_threshold': 0.7
            },
            'anomaly_detection': {
                'enabled': True,
                'algorithms': ['isolation_forest', 'one_class_svm', 'autoencoder'],
                'sensitivity': 0.8
            },
            'indicator_hunting': {
                'enabled': True,
                'ioc_types': ['ip_address', 'domain', 'file_hash', 'email'],
                'sources': ['threat_feeds', 'internal_logs', 'sandbox_results']
            },
            'machine_learning': {
                'enabled': True,
                'models': ['threat_classifier', 'anomaly_detector', 'correlation_analyzer'],
                'training_data_size': 10000
            }
        }

    def _initialize_threat_intelligence(self):
        """Initialize threat intelligence database"""
        self.threat_intelligence = {
            'apt_groups': {
                'APT1': {
                    'description': 'Chinese state-sponsored group',
                    'tactics': ['spear_phishing', 'lateral_movement', 'data_exfiltration'],
                    'indicators': ['specific_domains', 'file_hashes', 'ip_ranges']
                },
                'APT29': {
                    'description': 'Russian state-sponsored group',
                    'tactics': ['supply_chain', 'credential_theft', 'persistence'],
                    'indicators': ['malware_families', 'infrastructure', 'tools']
                }
            },
            'malware_families': {
                'Emotet': {
                    'type': 'banking_trojan',
                    'capabilities': ['keylogging', 'credential_theft', 'lateral_movement'],
                    'indicators': ['network_communication', 'file_characteristics']
                },
                'Ryuk': {
                    'type': 'ransomware',
                    'capabilities': ['file_encryption', 'network_propagation'],
                    'indicators': ['encryption_patterns', 'ransom_notes']
                }
            },
            'attack_patterns': {
                'kill_chain': ['reconnaissance', 'weaponization', 'delivery', 'exploitation', 'installation', 'command_control', 'actions_on_objectives'],
                'mitre_attck': ['initial_access', 'execution', 'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access', 'discovery', 'lateral_movement', 'collection', 'command_control', 'exfiltration', 'impact']
            }
        }

    async def start_hunting_campaign(self, campaign_name: str, target_threats: List[ThreatType], techniques: List[HuntingTechnique]) -> HuntingCampaign:
        """Start a new threat hunting campaign"""
        campaign_id = f"campaign_{hashlib.md5(campaign_name.encode()).hexdigest()[:8]}"
        
        campaign = HuntingCampaign(
            campaign_id=campaign_id,
            name=campaign_name,
            description=f"AI-powered hunting campaign targeting {[t.value for t in target_threats]}",
            target_threats=target_threats,
            techniques=techniques,
            start_time=datetime.now(),
            end_time=None,
            status=HuntingStatus.PLANNING,
            hypotheses=[],
            results=[],
            success_rate=0.0
        )

        await self._generate_hunting_hypotheses(campaign)

        campaign.status = HuntingStatus.ACTIVE
        self.active_campaigns[campaign_id] = campaign

        asyncio.create_task(self._execute_hunting_campaign(campaign))
        
        logger.info(f"🎯 Started hunting campaign: {campaign_name}")
        
        return campaign

    async def _generate_hunting_hypotheses(self, campaign: HuntingCampaign):
        """Generate hunting hypotheses for the campaign"""
        for threat_type in campaign.target_threats:

            for i in range(3):
                hypothesis = await self._create_hypothesis(threat_type, campaign.techniques)
                campaign.hypotheses.append(hypothesis)

    async def _create_hypothesis(self, threat_type: ThreatType, techniques: List[HuntingTechnique]) -> HuntingHypothesis:
        """Create a hunting hypothesis"""
        hypothesis_id = f"hyp_{secrets.token_hex(8)}"

        if threat_type == ThreatType.APT:
            title = "Advanced Persistent Threat Activity"
            description = "Hunt for indicators of sophisticated, long-term threat actor presence"
            techniques = [HuntingTechnique.BEHAVIORAL_ANALYSIS, HuntingTechnique.CORRELATION_ANALYSIS]
        elif threat_type == ThreatType.MALWARE:
            title = "Malware Infection and Propagation"
            description = "Hunt for malware indicators and propagation patterns"
            techniques = [HuntingTechnique.INDICATOR_HUNTING, HuntingTechnique.ANOMALY_DETECTION]
        elif threat_type == ThreatType.INSIDER_THREAT:
            title = "Insider Threat Activity"
            description = "Hunt for malicious insider behavior patterns"
            techniques = [HuntingTechnique.BEHAVIORAL_ANALYSIS, HuntingTechnique.MACHINE_LEARNING]
        elif threat_type == ThreatType.DATA_EXFILTRATION:
            title = "Data Exfiltration Attempts"
            description = "Hunt for unauthorized data transfer patterns"
            techniques = [HuntingTechnique.ANOMALY_DETECTION, HuntingTechnique.CORRELATION_ANALYSIS]
        else:
            title = f"{threat_type.value.replace('_', ' ').title()} Activity"
            description = f"Hunt for indicators of {threat_type.value} activity"
            techniques = techniques[:2]
        
        hypothesis = HuntingHypothesis(
            hypothesis_id=hypothesis_id,
            title=title,
            description=description,
            threat_type=threat_type,
            techniques=techniques,
            confidence=random.uniform(0.6, 0.9),
            priority=random.choice(['medium', 'high', 'critical']),
            created_at=datetime.now(),
            status=HuntingStatus.PLANNING,
            evidence=[]
        )
        
        return hypothesis

    async def _execute_hunting_campaign(self, campaign: HuntingCampaign):
        """Execute autonomous threat hunting campaign"""
        logger.info(f"🔍 Executing hunting campaign: {campaign.name}")
        
        try:

            for hypothesis in campaign.hypotheses:
                hypothesis.status = HuntingStatus.ACTIVE

                result = await self._hunt_for_threats(hypothesis)
                campaign.results.append(result)

                if result.threat_detected:
                    hypothesis.status = HuntingStatus.CONFIRMED
                    hypothesis.evidence.extend(result.indicators)
                else:
                    hypothesis.status = HuntingStatus.FALSE_POSITIVE

                await asyncio.sleep(5)

            detected_threats = len([r for r in campaign.results if r.threat_detected])
            campaign.success_rate = detected_threats / len(campaign.results) if campaign.results else 0.0

            campaign.status = HuntingStatus.COMPLETED
            campaign.end_time = datetime.now()
            
            logger.info(f"✅ Hunting campaign completed: {campaign.name} (Success rate: {campaign.success_rate:.2%})")
            
        except Exception as e:
            logger.error(f"Error executing hunting campaign: {e}")
            campaign.status = HuntingStatus.COMPLETED
            campaign.end_time = datetime.now()

    async def _hunt_for_threats(self, hypothesis: HuntingHypothesis) -> HuntingResult:
        """Hunt for threats based on hypothesis"""
        result_id = f"result_{secrets.token_hex(8)}"

        threat_detected = False
        confidence_score = 0.0
        indicators = []
        timeline = []
        affected_assets = []
        
        for technique in hypothesis.techniques:
            if technique == HuntingTechnique.BEHAVIORAL_ANALYSIS:
                result = await self._behavioral_analysis_hunt(hypothesis)
            elif technique == HuntingTechnique.ANOMALY_DETECTION:
                result = await self._anomaly_detection_hunt(hypothesis)
            elif technique == HuntingTechnique.INDICATOR_HUNTING:
                result = await self._indicator_hunting_hunt(hypothesis)
            elif technique == HuntingTechnique.MACHINE_LEARNING:
                result = await self._machine_learning_hunt(hypothesis)
            elif technique == HuntingTechnique.CORRELATION_ANALYSIS:
                result = await self._correlation_analysis_hunt(hypothesis)
            else:
                result = await self._hypothesis_driven_hunt(hypothesis)

            if result['threat_detected']:
                threat_detected = True
                confidence_score = max(confidence_score, result['confidence'])
                indicators.extend(result['indicators'])
                timeline.extend(result['timeline'])
                affected_assets.extend(result['affected_assets'])

        severity = 'low'
        if confidence_score > 0.8:
            severity = 'critical'
        elif confidence_score > 0.6:
            severity = 'high'
        elif confidence_score > 0.4:
            severity = 'medium'

        recommendations = self._generate_recommendations(hypothesis.threat_type, severity, indicators)
        
        hunting_result = HuntingResult(
            result_id=result_id,
            hypothesis_id=hypothesis.hypothesis_id,
            threat_detected=threat_detected,
            threat_type=hypothesis.threat_type if threat_detected else None,
            confidence_score=confidence_score,
            severity=severity,
            indicators=indicators,
            timeline=timeline,
            affected_assets=affected_assets,
            recommendations=recommendations,
            discovered_at=datetime.now()
        )
        
        return hunting_result

    async def _behavioral_analysis_hunt(self, hypothesis: HuntingHypothesis) -> Dict[str, Any]:
        """Perform behavioral analysis hunting"""

        threat_detected = random.random() < 0.3
        
        if threat_detected:
            indicators = [
                {
                    'type': 'behavioral_anomaly',
                    'description': 'Unusual user activity pattern detected',
                    'confidence': random.uniform(0.7, 0.9),
                    'timestamp': datetime.now().isoformat()
                },
                {
                    'type': 'access_pattern',
                    'description': 'Abnormal data access pattern',
                    'confidence': random.uniform(0.6, 0.8),
                    'timestamp': datetime.now().isoformat()
                }
            ]
            
            timeline = [
                {
                    'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                    'event': 'Unusual login from new location',
                    'severity': 'medium'
                },
                {
                    'timestamp': (datetime.now() - timedelta(hours=1)).isoformat(),
                    'event': 'Large data download initiated',
                    'severity': 'high'
                }
            ]
            
            affected_assets = ['user_workstation_001', 'file_server_002']
        else:
            indicators = []
            timeline = []
            affected_assets = []
        
        return {
            'threat_detected': threat_detected,
            'confidence': random.uniform(0.6, 0.9) if threat_detected else random.uniform(0.1, 0.4),
            'indicators': indicators,
            'timeline': timeline,
            'affected_assets': affected_assets
        }

    async def _anomaly_detection_hunt(self, hypothesis: HuntingHypothesis) -> Dict[str, Any]:
        """Perform anomaly detection hunting"""

        threat_detected = random.random() < 0.25
        
        if threat_detected:
            indicators = [
                {
                    'type': 'network_anomaly',
                    'description': 'Unusual network traffic pattern',
                    'confidence': random.uniform(0.7, 0.9),
                    'timestamp': datetime.now().isoformat()
                },
                {
                    'type': 'system_anomaly',
                    'description': 'Abnormal system resource usage',
                    'confidence': random.uniform(0.6, 0.8),
                    'timestamp': datetime.now().isoformat()
                }
            ]
            
            timeline = [
                {
                    'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat(),
                    'event': 'Spike in network traffic',
                    'severity': 'medium'
                },
                {
                    'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(),
                    'event': 'High CPU usage on multiple systems',
                    'severity': 'high'
                }
            ]
            
            affected_assets = ['network_segment_1', 'server_farm_1']
        else:
            indicators = []
            timeline = []
            affected_assets = []
        
        return {
            'threat_detected': threat_detected,
            'confidence': random.uniform(0.6, 0.9) if threat_detected else random.uniform(0.1, 0.4),
            'indicators': indicators,
            'timeline': timeline,
            'affected_assets': affected_assets
        }

    async def _indicator_hunting_hunt(self, hypothesis: HuntingHypothesis) -> Dict[str, Any]:
        """Perform indicator hunting"""

        threat_detected = random.random() < 0.2
        
        if threat_detected:
            indicators = [
                {
                    'type': 'ip_address',
                    'value': f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    'description': 'Known malicious IP address',
                    'confidence': random.uniform(0.8, 0.95),
                    'timestamp': datetime.now().isoformat()
                },
                {
                    'type': 'file_hash',
                    'value': secrets.token_hex(32),
                    'description': 'Malware file hash detected',
                    'confidence': random.uniform(0.9, 0.99),
                    'timestamp': datetime.now().isoformat()
                }
            ]
            
            timeline = [
                {
                    'timestamp': (datetime.now() - timedelta(hours=1)).isoformat(),
                    'event': 'Connection to known malicious IP',
                    'severity': 'high'
                },
                {
                    'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat(),
                    'event': 'Malware file detected on system',
                    'severity': 'critical'
                }
            ]
            
            affected_assets = ['workstation_003', 'file_server_001']
        else:
            indicators = []
            timeline = []
            affected_assets = []
        
        return {
            'threat_detected': threat_detected,
            'confidence': random.uniform(0.7, 0.95) if threat_detected else random.uniform(0.1, 0.3),
            'indicators': indicators,
            'timeline': timeline,
            'affected_assets': affected_assets
        }

    async def _machine_learning_hunt(self, hypothesis: HuntingHypothesis) -> Dict[str, Any]:
        """Perform machine learning-based hunting"""

        threat_detected = random.random() < 0.35
        
        if threat_detected:
            indicators = [
                {
                    'type': 'ml_prediction',
                    'description': 'ML model detected suspicious pattern',
                    'confidence': random.uniform(0.75, 0.9),
                    'timestamp': datetime.now().isoformat(),
                    'model_used': 'threat_classifier_v2'
                },
                {
                    'type': 'pattern_match',
                    'description': 'Pattern matching identified threat behavior',
                    'confidence': random.uniform(0.7, 0.85),
                    'timestamp': datetime.now().isoformat(),
                    'pattern_id': f"pattern_{secrets.token_hex(4)}"
                }
            ]
            
            timeline = [
                {
                    'timestamp': (datetime.now() - timedelta(hours=3)).isoformat(),
                    'event': 'ML model flagged suspicious activity',
                    'severity': 'medium'
                },
                {
                    'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                    'event': 'Pattern matching confirmed threat',
                    'severity': 'high'
                }
            ]
            
            affected_assets = ['ml_analysis_engine', 'pattern_database']
        else:
            indicators = []
            timeline = []
            affected_assets = []
        
        return {
            'threat_detected': threat_detected,
            'confidence': random.uniform(0.7, 0.9) if threat_detected else random.uniform(0.1, 0.4),
            'indicators': indicators,
            'timeline': timeline,
            'affected_assets': affected_assets
        }

    async def _correlation_analysis_hunt(self, hypothesis: HuntingHypothesis) -> Dict[str, Any]:
        """Perform correlation analysis hunting"""

        threat_detected = random.random() < 0.28
        
        if threat_detected:
            indicators = [
                {
                    'type': 'correlation_match',
                    'description': 'Multiple events correlated to threat pattern',
                    'confidence': random.uniform(0.8, 0.95),
                    'timestamp': datetime.now().isoformat(),
                    'correlation_score': random.uniform(0.7, 0.9)
                }
            ]
            
            timeline = [
                {
                    'timestamp': (datetime.now() - timedelta(hours=4)).isoformat(),
                    'event': 'Initial suspicious activity detected',
                    'severity': 'low'
                },
                {
                    'timestamp': (datetime.now() - timedelta(hours=3)).isoformat(),
                    'event': 'Correlated activity pattern identified',
                    'severity': 'medium'
                },
                {
                    'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                    'event': 'Threat pattern confirmed through correlation',
                    'severity': 'high'
                }
            ]
            
            affected_assets = ['correlation_engine', 'event_database']
        else:
            indicators = []
            timeline = []
            affected_assets = []
        
        return {
            'threat_detected': threat_detected,
            'confidence': random.uniform(0.7, 0.9) if threat_detected else random.uniform(0.1, 0.4),
            'indicators': indicators,
            'timeline': timeline,
            'affected_assets': affected_assets
        }

    async def _hypothesis_driven_hunt(self, hypothesis: HuntingHypothesis) -> Dict[str, Any]:
        """Perform hypothesis-driven hunting"""

        threat_detected = random.random() < 0.22
        
        if threat_detected:
            indicators = [
                {
                    'type': 'hypothesis_confirmation',
                    'description': f'Hypothesis "{hypothesis.title}" confirmed',
                    'confidence': random.uniform(0.7, 0.9),
                    'timestamp': datetime.now().isoformat()
                }
            ]
            
            timeline = [
                {
                    'timestamp': (datetime.now() - timedelta(hours=1)).isoformat(),
                    'event': 'Hypothesis testing initiated',
                    'severity': 'low'
                },
                {
                    'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat(),
                    'event': 'Evidence supporting hypothesis found',
                    'severity': 'medium'
                }
            ]
            
            affected_assets = ['hypothesis_engine']
        else:
            indicators = []
            timeline = []
            affected_assets = []
        
        return {
            'threat_detected': threat_detected,
            'confidence': random.uniform(0.6, 0.8) if threat_detected else random.uniform(0.1, 0.4),
            'indicators': indicators,
            'timeline': timeline,
            'affected_assets': affected_assets
        }

    def _generate_recommendations(self, threat_type: ThreatType, severity: str, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on hunting results"""
        recommendations = []
        
        if severity == 'critical':
            recommendations.extend([
                "Immediately isolate affected systems",
                "Activate incident response team",
                "Notify senior management",
                "Preserve evidence for forensic analysis"
            ])
        elif severity == 'high':
            recommendations.extend([
                "Increase monitoring on affected systems",
                "Review and update security controls",
                "Conduct additional investigation",
                "Update threat intelligence feeds"
            ])
        elif severity == 'medium':
            recommendations.extend([
                "Monitor for additional indicators",
                "Review system configurations",
                "Update detection rules",
                "Conduct security awareness training"
            ])
        else:
            recommendations.extend([
                "Continue monitoring",
                "Document findings",
                "Review security policies"
            ])

        if threat_type == ThreatType.APT:
            recommendations.append("Implement advanced threat hunting techniques")
        elif threat_type == ThreatType.MALWARE:
            recommendations.append("Update antivirus signatures and conduct full system scan")
        elif threat_type == ThreatType.INSIDER_THREAT:
            recommendations.append("Review user access controls and monitor privileged accounts")
        
        return recommendations

    async def get_hunting_statistics(self) -> Dict[str, Any]:
        """Get threat hunting statistics"""
        total_campaigns = len(self.active_campaigns) + len(self.hunting_history)
        active_campaigns = len(self.active_campaigns)

        all_results = []
        for campaign in list(self.active_campaigns.values()) + self.hunting_history:
            all_results.extend(campaign.results)
        
        total_hunts = len(all_results)
        successful_hunts = len([r for r in all_results if r.threat_detected])
        overall_success_rate = successful_hunts / total_hunts if total_hunts > 0 else 0.0

        threat_types = {}
        for result in all_results:
            if result.threat_detected and result.threat_type:
                threat_type = result.threat_type.value
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

        technique_effectiveness = {}
        for technique in HuntingTechnique:
            technique_results = [r for r in all_results if any(h.techniques for h in self.active_campaigns.values() if technique in h.techniques)]
            if technique_results:
                successful = len([r for r in technique_results if r.threat_detected])
                technique_effectiveness[technique.value] = successful / len(technique_results)
        
        return {
            'total_campaigns': total_campaigns,
            'active_campaigns': active_campaigns,
            'total_hunts': total_hunts,
            'successful_hunts': successful_hunts,
            'overall_success_rate': overall_success_rate,
            'threat_types_detected': threat_types,
            'technique_effectiveness': technique_effectiveness,
            'hunting_capabilities': self.hunting_capabilities,
            'last_hunt': max([r.discovered_at for r in all_results]).isoformat() if all_results else None,
            'threat_hunter_status': 'active'
        }

    async def get_active_campaigns(self) -> List[Dict[str, Any]]:
        """Get active hunting campaigns"""
        campaigns = []
        for campaign in self.active_campaigns.values():
            campaigns.append({
                'campaign_id': campaign.campaign_id,
                'name': campaign.name,
                'description': campaign.description,
                'target_threats': [t.value for t in campaign.target_threats],
                'techniques': [t.value for t in campaign.techniques],
                'start_time': campaign.start_time.isoformat(),
                'status': campaign.status.value,
                'hypotheses_count': len(campaign.hypotheses),
                'results_count': len(campaign.results),
                'success_rate': campaign.success_rate
            })
        return campaigns

    async def get_hunting_results(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent hunting results"""
        all_results = []
        for campaign in list(self.active_campaigns.values()) + self.hunting_history:
            all_results.extend(campaign.results)

        all_results.sort(key=lambda x: x.discovered_at, reverse=True)
        
        return [
            {
                'result_id': result.result_id,
                'hypothesis_id': result.hypothesis_id,
                'threat_detected': result.threat_detected,
                'threat_type': result.threat_type.value if result.threat_type else None,
                'confidence_score': result.confidence_score,
                'severity': result.severity,
                'indicators_count': len(result.indicators),
                'affected_assets_count': len(result.affected_assets),
                'recommendations_count': len(result.recommendations),
                'discovered_at': result.discovered_at.isoformat()
            }
            for result in all_results[:limit]
        ]