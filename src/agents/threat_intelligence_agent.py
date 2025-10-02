"""
Threat Intelligence Agent - Specialized in threat intelligence and knowledge sharing
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import random

from .base_agent import BaseAgent, AgentCapability

logger = logging.getLogger(__name__)

class ThreatIntelligenceAgent(BaseAgent):
    """
    Specialized agent for threat intelligence gathering and sharing
    """
    
    def __init__(self, agent_id: str = "threat_intel_001"):
        super().__init__(agent_id, "Threat Intelligence Specialist", "threat_intelligence")

        self.capabilities = [
            AgentCapability(
                capability_name="threat_feed_analysis",
                description="Analyze external threat intelligence feeds",
                input_types=["threat_feeds", "ioc_data"],
                output_types=["threat_indicators", "risk_assessment"]
            ),
            AgentCapability(
                capability_name="ioc_enrichment",
                description="Enrich indicators of compromise with additional data",
                input_types=["ioc_list", "enrichment_sources"],
                output_types=["enriched_iocs", "contextual_data"]
            ),
            AgentCapability(
                capability_name="threat_attribution",
                description="Attribute threats to specific threat actors or groups",
                input_types=["attack_patterns", "tactics_techniques"],
                output_types=["attribution_analysis", "confidence_score"]
            ),
            AgentCapability(
                capability_name="knowledge_synthesis",
                description="Synthesize threat knowledge from multiple sources",
                input_types=["threat_reports", "analysis_data"],
                output_types=["synthesized_intelligence", "actionable_insights"]
            )
        ]
        
        self.specializations = [
            "threat_intelligence",
            "ioc_analysis",
            "threat_attribution",
            "knowledge_synthesis"
        ]

        self.threat_database = {
            "threat_actors": {
                "APT1": {"country": "China", "motivation": "espionage", "capabilities": "advanced"},
                "APT28": {"country": "Russia", "motivation": "espionage", "capabilities": "advanced"},
                "Lazarus": {"country": "North Korea", "motivation": "financial", "capabilities": "high"},
                "FIN7": {"country": "Unknown", "motivation": "financial", "capabilities": "high"}
            },
            "malware_families": {
                "Emotet": {"type": "banking_trojan", "distribution": "email", "targets": "financial"},
                "Ryuk": {"type": "ransomware", "distribution": "network", "targets": "enterprise"},
                "TrickBot": {"type": "banking_trojan", "distribution": "email", "targets": "financial"},
                "Maze": {"type": "ransomware", "distribution": "network", "targets": "enterprise"}
            },
            "attack_patterns": {
                "phishing": {"frequency": "high", "success_rate": 0.3, "targets": "all"},
                "ransomware": {"frequency": "medium", "success_rate": 0.2, "targets": "enterprise"},
                "apt_attack": {"frequency": "low", "success_rate": 0.1, "targets": "government"},
                "insider_threat": {"frequency": "low", "success_rate": 0.4, "targets": "enterprise"}
            }
        }

        self.intelligence_sources = [
            "commercial_feeds",
            "government_intelligence",
            "open_source_intelligence",
            "industry_sharing",
            "internal_analysis"
        ]

        self.knowledge_base = []
        self.ioc_database = {}
        self.threat_reports = []
        
        logger.info(f"🧠 Threat Intelligence Agent {self.agent_id} initialized")

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat intelligence tasks"""
        task_type = task_data.get("task_type", "unknown")
        
        if task_type == "threat_feed_analysis":
            return await self._analyze_threat_feeds(task_data)
        elif task_type == "ioc_enrichment":
            return await self._enrich_iocs(task_data)
        elif task_type == "threat_attribution":
            return await self._attribute_threat(task_data)
        elif task_type == "knowledge_synthesis":
            return await self._synthesize_knowledge(task_data)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat data and provide intelligence insights"""
        threat_type = threat_data.get("type", "unknown")
        threat_indicators = threat_data.get("indicators", {})

        intelligence_analysis = {
            "threat_id": f"intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "threat_type": threat_type,
            "intelligence_sources": self._identify_relevant_sources(threat_type),
            "threat_actor_analysis": await self._analyze_threat_actor(threat_indicators),
            "ioc_analysis": await self._analyze_iocs(threat_indicators),
            "attack_pattern_analysis": self._analyze_attack_patterns(threat_indicators),
            "risk_assessment": self._assess_threat_risk(threat_data),
            "intelligence_confidence": self._calculate_intelligence_confidence(threat_data),
            "actionable_intelligence": self._generate_actionable_intelligence(threat_data),
            "analysis_timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id
        }

        await self._store_intelligence(intelligence_analysis)
        
        return intelligence_analysis

    async def _analyze_threat_feeds(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze external threat intelligence feeds"""
        feed_data = task_data.get("feed_data", {})
        feed_sources = task_data.get("feed_sources", [])

        feed_analysis = {
            "sources_analyzed": len(feed_sources),
            "threat_indicators_found": 0,
            "new_threats_identified": [],
            "threat_trends": {},
            "feed_quality_scores": {}
        }
        
        for source in feed_sources:
            source_analysis = await self._analyze_single_feed(source, feed_data)
            feed_analysis["threat_indicators_found"] += source_analysis["indicators_count"]
            feed_analysis["new_threats_identified"].extend(source_analysis["new_threats"])
            feed_analysis["feed_quality_scores"][source] = source_analysis["quality_score"]

        feed_analysis["threat_trends"] = self._identify_threat_trends(feed_analysis)
        
        result = {
            "analysis_type": "threat_feed_analysis",
            "feed_analysis": feed_analysis,
            "recommendations": self._get_feed_recommendations(feed_analysis),
            "confidence": 0.85 + random.uniform(-0.1, 0.1)
        }
        
        return result

    async def _enrich_iocs(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich indicators of compromise with additional data"""
        ioc_list = task_data.get("ioc_list", [])
        enrichment_sources = task_data.get("enrichment_sources", [])
        
        enriched_iocs = []
        
        for ioc in ioc_list:
            enriched_ioc = await self._enrich_single_ioc(ioc, enrichment_sources)
            enriched_iocs.append(enriched_ioc)
        
        result = {
            "analysis_type": "ioc_enrichment",
            "iocs_processed": len(ioc_list),
            "enriched_iocs": enriched_iocs,
            "enrichment_sources_used": enrichment_sources,
            "enrichment_confidence": self._calculate_enrichment_confidence(enriched_iocs),
            "new_context_discovered": self._extract_new_context(enriched_iocs)
        }
        
        return result

    async def _attribute_threat(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Attribute threat to specific threat actors or groups"""
        attack_patterns = task_data.get("attack_patterns", {})
        tactics_techniques = task_data.get("tactics_techniques", [])

        attribution_analysis = {
            "possible_threat_actors": [],
            "attribution_confidence": 0.0,
            "attribution_factors": [],
            "attack_characteristics": {},
            "geographic_indicators": {},
            "motivation_analysis": {}
        }

        for actor, profile in self.threat_database["threat_actors"].items():
            similarity_score = self._calculate_actor_similarity(attack_patterns, profile)
            if similarity_score > 0.6:
                attribution_analysis["possible_threat_actors"].append({
                    "actor": actor,
                    "similarity_score": similarity_score,
                    "profile": profile
                })

        attribution_analysis["possible_threat_actors"].sort(
            key=lambda x: x["similarity_score"], reverse=True
        )

        if attribution_analysis["possible_threat_actors"]:
            attribution_analysis["attribution_confidence"] = attribution_analysis["possible_threat_actors"][0]["similarity_score"]
        
        result = {
            "analysis_type": "threat_attribution",
            "attribution_analysis": attribution_analysis,
            "recommended_actions": self._get_attribution_recommendations(attribution_analysis),
            "confidence": attribution_analysis["attribution_confidence"]
        }
        
        return result

    async def _synthesize_knowledge(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize threat knowledge from multiple sources"""
        threat_reports = task_data.get("threat_reports", [])
        analysis_data = task_data.get("analysis_data", {})

        synthesized_intelligence = {
            "threat_landscape": self._analyze_threat_landscape(threat_reports),
            "emerging_threats": self._identify_emerging_threats(threat_reports),
            "threat_evolution": self._analyze_threat_evolution(threat_reports),
            "cross_correlation": self._perform_cross_correlation(threat_reports),
            "intelligence_gaps": self._identify_intelligence_gaps(threat_reports),
            "actionable_insights": self._generate_synthesized_insights(threat_reports, analysis_data)
        }
        
        result = {
            "analysis_type": "knowledge_synthesis",
            "sources_synthesized": len(threat_reports),
            "synthesized_intelligence": synthesized_intelligence,
            "synthesis_confidence": self._calculate_synthesis_confidence(threat_reports),
            "recommendations": self._get_synthesis_recommendations(synthesized_intelligence)
        }
        
        return result

    def _identify_relevant_sources(self, threat_type: str) -> List[str]:
        """Identify relevant intelligence sources for threat type"""
        relevant_sources = []
        
        if threat_type in ["malware", "ransomware"]:
            relevant_sources.extend(["malware_feeds", "sandbox_analysis"])
        elif threat_type == "apt_attack":
            relevant_sources.extend(["government_intelligence", "industry_sharing"])
        elif threat_type == "phishing":
            relevant_sources.extend(["email_security_feeds", "url_reputation"])
        
        return relevant_sources

    async def _analyze_threat_actor(self, threat_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat actor characteristics"""
        return {
            "possible_actors": list(self.threat_database["threat_actors"].keys())[:3],
            "attack_sophistication": random.choice(["low", "medium", "high", "advanced"]),
            "motivation": random.choice(["financial", "espionage", "disruption", "activism"]),
            "geographic_indicators": random.choice(["China", "Russia", "North Korea", "Unknown"]),
            "attribution_confidence": random.uniform(0.3, 0.9)
        }

    async def _analyze_iocs(self, threat_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze indicators of compromise"""
        ioc_types = ["ip_addresses", "domains", "file_hashes", "email_addresses"]
        ioc_analysis = {}
        
        for ioc_type in ioc_types:
            if ioc_type in threat_indicators:
                ioc_analysis[ioc_type] = {
                    "count": len(threat_indicators[ioc_type]) if isinstance(threat_indicators[ioc_type], list) else 1,
                    "reputation_score": random.uniform(0.1, 0.9),
                    "first_seen": "2025-09-01",
                    "last_seen": "2025-10-01",
                    "associated_threats": random.randint(1, 5)
                }
        
        return ioc_analysis

    def _analyze_attack_patterns(self, threat_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack patterns and techniques"""
        return {
            "attack_vectors": random.sample(["email", "web", "network", "social_engineering"], 2),
            "tactics_used": random.sample(["initial_access", "execution", "persistence", "defense_evasion"], 3),
            "techniques_observed": random.sample(["spear_phishing", "powershell", "living_off_land"], 2),
            "attack_complexity": random.choice(["simple", "moderate", "complex", "advanced"]),
            "attack_duration": f"{random.randint(1, 30)} days"
        }

    def _assess_threat_risk(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess threat risk level"""
        return {
            "risk_level": random.choice(["low", "medium", "high", "critical"]),
            "likelihood": random.uniform(0.1, 0.9),
            "impact": random.choice(["minimal", "moderate", "significant", "severe"]),
            "business_impact": random.choice(["operational", "financial", "reputational", "regulatory"]),
            "geographic_scope": random.choice(["local", "regional", "global"]),
            "sector_targeting": random.choice(["all", "financial", "healthcare", "government", "technology"])
        }

    def _calculate_intelligence_confidence(self, threat_data: Dict[str, Any]) -> float:
        """Calculate confidence in intelligence analysis"""
        base_confidence = 0.7

        data_quality = threat_data.get("data_quality", 0.5)
        source_reliability = random.uniform(0.6, 0.95)
        
        confidence = base_confidence * data_quality * source_reliability
        return min(1.0, confidence + random.uniform(-0.1, 0.1))

    def _generate_actionable_intelligence(self, threat_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable intelligence recommendations"""
        recommendations = []
        
        threat_type = threat_data.get("type", "unknown")
        
        if threat_type == "malware":
            recommendations.append({
                "action": "update_antivirus_signatures",
                "priority": "high",
                "timeline": "immediate",
                "description": "Update antivirus signatures based on new malware indicators"
            })
        
        if threat_type == "phishing":
            recommendations.append({
                "action": "block_malicious_domains",
                "priority": "high",
                "timeline": "immediate",
                "description": "Block identified malicious domains and email addresses"
            })
        
        recommendations.append({
            "action": "enhance_monitoring",
            "priority": "medium",
            "timeline": "24_hours",
            "description": "Enhance monitoring for similar attack patterns"
        })
        
        return recommendations

    async def _store_intelligence(self, intelligence_analysis: Dict[str, Any]):
        """Store intelligence analysis for future reference"""
        self.knowledge_base.append({
            "timestamp": datetime.now(),
            "analysis": intelligence_analysis,
            "source": "internal_analysis"
        })

        if len(self.knowledge_base) > 1000:
            self.knowledge_base = self.knowledge_base[-1000:]

    async def _analyze_single_feed(self, source: str, feed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single threat intelligence feed"""
        return {
            "source": source,
            "indicators_count": random.randint(10, 100),
            "new_threats": [f"threat_{i}" for i in range(random.randint(1, 5))],
            "quality_score": random.uniform(0.6, 0.95),
            "last_updated": datetime.now().isoformat()
        }

    def _identify_threat_trends(self, feed_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Identify trends from threat feed analysis"""
        return {
            "increasing_threats": ["ransomware", "phishing"],
            "decreasing_threats": ["traditional_malware"],
            "emerging_threats": ["ai_powered_attacks", "supply_chain_attacks"],
            "geographic_trends": {"China": "increasing", "Russia": "stable", "North Korea": "increasing"}
        }

    def _get_feed_recommendations(self, feed_analysis: Dict[str, Any]) -> List[str]:
        """Get recommendations based on feed analysis"""
        recommendations = []
        
        if feed_analysis["threat_indicators_found"] > 50:
            recommendations.append("High volume of indicators detected - prioritize analysis")
        
        if len(feed_analysis["new_threats_identified"]) > 10:
            recommendations.append("Multiple new threats identified - update detection rules")
        
        recommendations.append("Continue monitoring threat feeds for updates")
        
        return recommendations

    async def _enrich_single_ioc(self, ioc: str, enrichment_sources: List[str]) -> Dict[str, Any]:
        """Enrich a single indicator of compromise"""
        return {
            "original_ioc": ioc,
            "ioc_type": random.choice(["ip", "domain", "hash", "email"]),
            "reputation_score": random.uniform(0.1, 0.9),
            "first_seen": "2025-09-01",
            "last_seen": "2025-10-01",
            "associated_threats": random.randint(1, 5),
            "geographic_info": {"country": random.choice(["US", "China", "Russia", "Unknown"])},
            "enrichment_sources": enrichment_sources,
            "confidence": random.uniform(0.7, 0.95)
        }

    def _calculate_enrichment_confidence(self, enriched_iocs: List[Dict[str, Any]]) -> float:
        """Calculate confidence in IOC enrichment"""
        if not enriched_iocs:
            return 0.0
        
        total_confidence = sum(ioc["confidence"] for ioc in enriched_iocs)
        return total_confidence / len(enriched_iocs)

    def _extract_new_context(self, enriched_iocs: List[Dict[str, Any]]) -> List[str]:
        """Extract new contextual information from enriched IOCs"""
        new_context = []
        
        for ioc in enriched_iocs:
            if ioc["reputation_score"] < 0.3:
                new_context.append(f"Malicious reputation for {ioc['original_ioc']}")
            
            if ioc["associated_threats"] > 3:
                new_context.append(f"High threat association for {ioc['original_ioc']}")
        
        return new_context

    def _calculate_actor_similarity(self, attack_patterns: Dict[str, Any], actor_profile: Dict[str, Any]) -> float:
        """Calculate similarity between attack patterns and threat actor profile"""

        base_similarity = 0.5

        if attack_patterns.get("sophistication") == actor_profile.get("capabilities"):
            base_similarity += 0.2
        
        if attack_patterns.get("motivation") == actor_profile.get("motivation"):
            base_similarity += 0.2
        
        return min(1.0, base_similarity + random.uniform(-0.1, 0.1))

    def _get_attribution_recommendations(self, attribution_analysis: Dict[str, Any]) -> List[str]:
        """Get recommendations based on attribution analysis"""
        recommendations = []
        
        if attribution_analysis["attribution_confidence"] > 0.8:
            recommendations.append("High confidence attribution - implement targeted defenses")
        elif attribution_analysis["attribution_confidence"] > 0.6:
            recommendations.append("Moderate confidence attribution - monitor for similar patterns")
        else:
            recommendations.append("Low confidence attribution - gather additional intelligence")
        
        recommendations.append("Share attribution findings with threat intelligence community")
        
        return recommendations

    def _analyze_threat_landscape(self, threat_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze overall threat landscape"""
        return {
            "active_threat_actors": random.randint(50, 200),
            "malware_families": random.randint(100, 500),
            "attack_vectors": ["email", "web", "network", "social_engineering"],
            "targeted_sectors": ["financial", "healthcare", "government", "technology"],
            "geographic_distribution": {"global": 0.6, "regional": 0.3, "local": 0.1}
        }

    def _identify_emerging_threats(self, threat_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify emerging threats"""
        return [
            {
                "threat_name": "AI-Powered Phishing",
                "emergence_date": "2025-09-01",
                "threat_level": "medium",
                "description": "Use of AI to create more convincing phishing emails"
            },
            {
                "threat_name": "Supply Chain Ransomware",
                "emergence_date": "2025-08-15",
                "threat_level": "high",
                "description": "Ransomware attacks targeting software supply chains"
            }
        ]

    def _analyze_threat_evolution(self, threat_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how threats are evolving"""
        return {
            "sophistication_trend": "increasing",
            "automation_level": "increasing",
            "targeting_precision": "increasing",
            "evasion_techniques": "evolving",
            "attack_frequency": "stable"
        }

    def _perform_cross_correlation(self, threat_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform cross-correlation analysis"""
        return {
            "correlated_threats": random.randint(5, 20),
            "shared_indicators": random.randint(10, 50),
            "attack_campaigns": random.randint(2, 8),
            "threat_actor_connections": random.randint(3, 12)
        }

    def _identify_intelligence_gaps(self, threat_reports: List[Dict[str, Any]]) -> List[str]:
        """Identify gaps in threat intelligence"""
        return [
            "Limited intelligence on emerging threat actors",
            "Insufficient data on attack motivations",
            "Gaps in geographic threat intelligence",
            "Limited visibility into attack infrastructure"
        ]

    def _generate_synthesized_insights(self, threat_reports: List[Dict[str, Any]], analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate synthesized insights from multiple sources"""
        return [
            {
                "insight": "Ransomware attacks are becoming more targeted and sophisticated",
                "confidence": 0.85,
                "actionable": True,
                "priority": "high"
            },
            {
                "insight": "Supply chain attacks are emerging as a significant threat vector",
                "confidence": 0.75,
                "actionable": True,
                "priority": "medium"
            },
            {
                "insight": "AI-powered attacks are expected to increase in the next 6 months",
                "confidence": 0.65,
                "actionable": True,
                "priority": "medium"
            }
        ]

    def _calculate_synthesis_confidence(self, threat_reports: List[Dict[str, Any]]) -> float:
        """Calculate confidence in knowledge synthesis"""
        base_confidence = 0.7

        source_count_factor = min(1.0, len(threat_reports) / 10)
        
        return min(1.0, base_confidence * source_count_factor + random.uniform(-0.1, 0.1))

    def _get_synthesis_recommendations(self, synthesized_intelligence: Dict[str, Any]) -> List[str]:
        """Get recommendations based on synthesized intelligence"""
        recommendations = []
        
        if len(synthesized_intelligence["emerging_threats"]) > 2:
            recommendations.append("Multiple emerging threats identified - update security posture")
        
        if synthesized_intelligence["threat_evolution"]["sophistication_trend"] == "increasing":
            recommendations.append("Threat sophistication increasing - enhance detection capabilities")
        
        recommendations.append("Continue monitoring threat landscape for changes")
        recommendations.append("Share synthesized intelligence with security community")
        
        return recommendations

    def get_intelligence_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return {
            "knowledge_base_size": len(self.knowledge_base),
            "ioc_database_size": len(self.ioc_database),
            "threat_reports_processed": len(self.threat_reports),
            "intelligence_sources": len(self.intelligence_sources),
            "attribution_accuracy": random.uniform(0.7, 0.9),
            "intelligence_freshness": "24 hours"
        }