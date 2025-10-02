"""
Multi-Agent Cybersecurity System - Main orchestrator for all agents
"""

import asyncio
import logging
import random
from datetime import datetime
from typing import Dict, List, Any, Optional
import json

from .multi_agent_coordinator import MultiAgentCoordinator
from .threat_detection_agent import ThreatDetectionAgent
from .response_coordination_agent import ResponseCoordinationAgent
from .threat_intelligence_agent import ThreatIntelligenceAgent

logger = logging.getLogger(__name__)

class MultiAgentCybersecuritySystem:
    """
    Main system that orchestrates all cybersecurity agents
    """
    
    def __init__(self):
        self.system_id = "multi_agent_cybersecurity_system"
        self.system_name = "Multi-Agent Cybersecurity Specialist"
        self.is_active = False
        
        # Initialize coordinator
        self.coordinator = MultiAgentCoordinator("coordinator_001")
        
        # Initialize specialized agents
        self.agents = {
            "threat_detection": ThreatDetectionAgent("threat_detector_001"),
            "response_coordination": ResponseCoordinationAgent("response_coordinator_001"),
            "threat_intelligence": ThreatIntelligenceAgent("threat_intel_001")
        }
        
        # System state
        self.system_stats = {
            "total_threats_analyzed": 0,
            "successful_responses": 0,
            "agent_collaborations": 0,
            "system_uptime_start": datetime.now(),
            "active_workflows": 0,
            "decisions_made": 0
        }
        
        # Performance metrics
        self.performance_metrics = {
            "threat_detection_accuracy": 0.95,
            "response_success_rate": 0.92,
            "intelligence_quality": 0.88,
            "coordination_efficiency": 0.90
        }
        
        logger.info(f"🤖 Multi-Agent Cybersecurity System initialized with {len(self.agents)} specialized agents")

    async def start_system(self):
        """Start the multi-agent cybersecurity system"""
        self.is_active = True
        logger.info("🚀 Starting Multi-Agent Cybersecurity System...")
        
        # Start all agents
        for agent_name, agent in self.agents.items():
            await agent.start_learning_mode()
            logger.info(f"✅ {agent_name} agent started")
        
        # Start coordinator
        await self.coordinator.start_learning_mode()
        logger.info("✅ Multi-Agent Coordinator started")
        
        # Start monitoring tasks
        asyncio.create_task(self._monitor_system_performance())
        asyncio.create_task(self._facilitate_agent_collaboration())
        
        logger.info("🎯 Multi-Agent Cybersecurity System is now active!")

    async def stop_system(self):
        """Stop the multi-agent cybersecurity system"""
        self.is_active = False
        logger.info("🛑 Stopping Multi-Agent Cybersecurity System...")
        
        # Stop all agents
        for agent_name, agent in self.agents.items():
            await agent.stop_learning_mode()
            logger.info(f"⏹️ {agent_name} agent stopped")
        
        # Stop coordinator
        await self.coordinator.stop_learning_mode()
        logger.info("⏹️ Multi-Agent Coordinator stopped")
        
        logger.info("✅ Multi-Agent Cybersecurity System stopped")

    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat using coordinated multi-agent approach"""
        if not self.is_active:
            return {"error": "System is not active"}
        
        self.system_stats["total_threats_analyzed"] += 1
        
        # Use coordinator to orchestrate multi-agent analysis
        coordinated_analysis = await self.coordinator.analyze_threat(threat_data)
        
        # Update system statistics
        if coordinated_analysis.get("final_decision", {}).get("decision_confidence", 0) > 0.7:
            self.system_stats["successful_responses"] += 1
        
        self.system_stats["decisions_made"] += 1
        
        # Add system-level metadata
        coordinated_analysis["system_metadata"] = {
            "system_id": self.system_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "agents_involved": list(self.agents.keys()),
            "system_confidence": self._calculate_system_confidence(coordinated_analysis),
            "collaboration_quality": self._assess_collaboration_quality(coordinated_analysis)
        }
        
        return coordinated_analysis

    async def process_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process security incident using multi-agent coordination"""
        if not self.is_active:
            return {"error": "System is not active"}
        
        # Create incident processing workflow
        incident_result = await self.coordinator.process_task({
            "task_type": "incident_response",
            "incident_data": incident_data
        })
        
        # Update system statistics
        self.system_stats["agent_collaborations"] += 1
        
        return incident_result

    async def conduct_threat_hunting(self, hunting_parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Conduct proactive threat hunting using coordinated agents"""
        if not self.is_active:
            return {"error": "System is not active"}
        
        # Create threat hunting workflow
        hunting_result = await self.coordinator.process_task({
            "task_type": "threat_hunting",
            "hunting_parameters": hunting_parameters
        })
        
        return hunting_result

    async def optimize_system_performance(self) -> Dict[str, Any]:
        """Optimize overall system performance"""
        if not self.is_active:
            return {"error": "System is not active"}
        
        # Use coordinator to optimize agent performance
        optimization_result = await self.coordinator.process_task({
            "task_type": "agent_optimization"
        })
        
        # Update performance metrics
        self._update_performance_metrics(optimization_result)
        
        return optimization_result

    async def _monitor_system_performance(self):
        """Monitor system performance continuously"""
        while self.is_active:
            try:
                # Collect performance data from all agents
                performance_data = await self._collect_performance_data()
                
                # Analyze performance trends
                performance_analysis = self._analyze_performance_trends(performance_data)
                
                # Trigger optimizations if needed
                if performance_analysis.get("optimization_needed", False):
                    await self.optimize_system_performance()
                
                await asyncio.sleep(300)  # Monitor every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in system performance monitoring: {e}")
                await asyncio.sleep(60)

    async def _facilitate_agent_collaboration(self):
        """Facilitate collaboration between agents"""
        while self.is_active:
            try:
                # Check for collaboration opportunities
                collaboration_opportunities = self._identify_collaboration_opportunities()
                
                # Facilitate knowledge sharing
                if collaboration_opportunities:
                    await self._facilitate_knowledge_sharing(collaboration_opportunities)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in agent collaboration: {e}")
                await asyncio.sleep(30)

    async def _collect_performance_data(self) -> Dict[str, Any]:
        """Collect performance data from all agents"""
        performance_data = {}
        
        # Collect from individual agents
        for agent_name, agent in self.agents.items():
            performance_data[agent_name] = agent.get_status()
        
        # Collect from coordinator
        performance_data["coordinator"] = self.coordinator.get_status()
        
        return performance_data

    def _analyze_performance_trends(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze performance trends and identify issues"""
        analysis = {
            "overall_performance": 0.0,
            "agent_performances": {},
            "optimization_needed": False,
            "performance_issues": []
        }
        
        total_performance = 0.0
        agent_count = 0
        
        for agent_name, agent_data in performance_data.items():
            if hasattr(agent_data, 'performance_score'):
                performance_score = agent_data.performance_score
                analysis["agent_performances"][agent_name] = performance_score
                total_performance += performance_score
                agent_count += 1
                
                # Check for performance issues
                if performance_score < 0.7:
                    analysis["performance_issues"].append({
                        "agent": agent_name,
                        "issue": "low_performance",
                        "score": performance_score
                    })
                    analysis["optimization_needed"] = True
        
        if agent_count > 0:
            analysis["overall_performance"] = total_performance / agent_count
        
        return analysis

    def _identify_collaboration_opportunities(self) -> List[Dict[str, Any]]:
        """Identify opportunities for agent collaboration"""
        opportunities = []
        
        # Check if agents have complementary knowledge
        agent_statuses = {}
        for agent_name, agent in self.agents.items():
            agent_statuses[agent_name] = agent.get_status()
        
        # Identify agents that could benefit from knowledge sharing
        for agent_name, status in agent_statuses.items():
            if status.performance_score < 0.8:
                opportunities.append({
                    "type": "knowledge_sharing",
                    "target_agent": agent_name,
                    "reason": "performance_improvement"
                })
        
        return opportunities

    async def _facilitate_knowledge_sharing(self, opportunities: List[Dict[str, Any]]):
        """Facilitate knowledge sharing between agents"""
        for opportunity in opportunities:
            if opportunity["type"] == "knowledge_sharing":
                target_agent = opportunity["target_agent"]
                
                # Find agents with high performance to share knowledge
                for agent_name, agent in self.agents.items():
                    if agent_name != target_agent and agent.get_status().performance_score > 0.8:
                        # Share knowledge
                        knowledge = {
                            "quality": 0.8,
                            "type": "performance_insights",
                            "source": agent_name
                        }
                        await agent.share_knowledge(target_agent, knowledge)
                        logger.info(f"📚 Knowledge shared from {agent_name} to {target_agent}")

    def _calculate_system_confidence(self, coordinated_analysis: Dict[str, Any]) -> float:
        """Calculate overall system confidence"""
        final_decision = coordinated_analysis.get("final_decision", {})
        decision_confidence = final_decision.get("decision_confidence", 0.5)
        coordination_confidence = coordinated_analysis.get("coordination_confidence", 0.5)
        
        # Weight coordination confidence more heavily
        return (decision_confidence * 0.6) + (coordination_confidence * 0.4)

    def _assess_collaboration_quality(self, coordinated_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the quality of agent collaboration"""
        agent_analyses = coordinated_analysis.get("agent_analyses", {})
        synthesized_analysis = coordinated_analysis.get("synthesized_analysis", {})
        
        return {
            "agents_involved": len(agent_analyses),
            "consensus_level": len(synthesized_analysis.get("consensus_areas", [])),
            "conflict_resolution": len(synthesized_analysis.get("conflicting_insights", [])),
            "collaboration_score": random.uniform(0.8, 0.95)  # Simulated
        }

    def _update_performance_metrics(self, optimization_result: Dict[str, Any]):
        """Update system performance metrics based on optimization results"""
        performance_improvement = optimization_result.get("performance_improvement", {})
        
        # Update metrics
        for metric, improvement in performance_improvement.items():
            if metric in self.performance_metrics:
                self.performance_metrics[metric] = min(1.0, 
                    self.performance_metrics[metric] + improvement)

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        uptime = datetime.now() - self.system_stats["system_uptime_start"]
        
        # Create serializable system stats
        serializable_stats = self.system_stats.copy()
        serializable_stats["system_uptime_start"] = self.system_stats["system_uptime_start"].isoformat()
        
        # Create serializable agent statuses
        serializable_agent_statuses = {}
        for agent_name, agent in self.agents.items():
            agent_status = agent.get_status()
            serializable_agent_statuses[agent_name] = {
                "agent_id": agent_status.agent_id,
                "status": agent_status.status,
                "current_task": agent_status.current_task,
                "performance_score": agent_status.performance_score,
                "last_activity": agent_status.last_activity.isoformat(),
                "messages_processed": agent_status.messages_processed,
                "tasks_completed": agent_status.tasks_completed,
                "errors_count": agent_status.errors_count
            }
        
        # Create serializable coordinator status
        coordinator_status = self.coordinator.get_status()
        serializable_coordinator_status = {
            "agent_id": coordinator_status.agent_id,
            "status": coordinator_status.status,
            "current_task": coordinator_status.current_task,
            "performance_score": coordinator_status.performance_score,
            "last_activity": coordinator_status.last_activity.isoformat(),
            "messages_processed": coordinator_status.messages_processed,
            "tasks_completed": coordinator_status.tasks_completed,
            "errors_count": coordinator_status.errors_count
        }
        
        return {
            "system_id": self.system_id,
            "system_name": self.system_name,
            "status": "active" if self.is_active else "inactive",
            "uptime_seconds": uptime.total_seconds(),
            "system_statistics": serializable_stats,
            "performance_metrics": self.performance_metrics,
            "agent_statuses": serializable_agent_statuses,
            "coordinator_status": serializable_coordinator_status,
            "active_workflows": len(self.coordinator.active_workflows),
            "system_health": self._calculate_system_health()
        }

    def _calculate_system_health(self) -> Dict[str, Any]:
        """Calculate overall system health"""
        health_score = 0.0
        health_factors = []
        
        # Factor in agent performance
        for agent_name, agent in self.agents.items():
            agent_performance = agent.get_status().performance_score
            health_score += agent_performance
            health_factors.append(f"{agent_name}_performance")
        
        # Factor in coordinator performance
        coordinator_performance = self.coordinator.get_status().performance_score
        health_score += coordinator_performance
        health_factors.append("coordinator_performance")
        
        # Calculate average
        total_agents = len(self.agents) + 1  # +1 for coordinator
        health_score = health_score / total_agents
        
        return {
            "overall_health": health_score,
            "health_level": "excellent" if health_score > 0.9 else 
                          "good" if health_score > 0.8 else 
                          "fair" if health_score > 0.7 else "poor",
            "health_factors": health_factors,
            "recommendations": self._get_health_recommendations(health_score)
        }

    def _get_health_recommendations(self, health_score: float) -> List[str]:
        """Get recommendations based on system health"""
        recommendations = []
        
        if health_score < 0.8:
            recommendations.append("Consider running system optimization")
        
        if health_score < 0.7:
            recommendations.append("Review agent performance and consider retraining")
        
        if health_score < 0.6:
            recommendations.append("Immediate system maintenance required")
        
        return recommendations

    def get_agent_capabilities(self) -> Dict[str, Any]:
        """Get capabilities of all agents"""
        capabilities = {}
        
        for agent_name, agent in self.agents.items():
            capabilities[agent_name] = {
                "agent_info": agent.get_agent_info(),
                "capabilities": [cap.__dict__ for cap in agent.get_capabilities()]
            }
        
        capabilities["coordinator"] = {
            "agent_info": self.coordinator.get_agent_info(),
            "capabilities": [cap.__dict__ for cap in self.coordinator.get_capabilities()]
        }
        
        return capabilities

    def get_system_analytics(self) -> Dict[str, Any]:
        """Get comprehensive system analytics"""
        # Get analytics from agents
        threat_analytics = self.agents["threat_detection"].get_detection_statistics()
        response_analytics = self.agents["response_coordination"].get_response_statistics()
        intel_analytics = self.agents["threat_intelligence"].get_intelligence_statistics()
        coord_analytics = self.coordinator.get_coordination_statistics()
        
        # Make sure all datetime objects are serialized
        def serialize_analytics(analytics):
            if isinstance(analytics, dict):
                serialized = {}
                for key, value in analytics.items():
                    if isinstance(value, datetime):
                        serialized[key] = value.isoformat()
                    elif isinstance(value, dict):
                        serialized[key] = serialize_analytics(value)
                    else:
                        serialized[key] = value
                return serialized
            return analytics
        
        return {
            "threat_analysis_analytics": serialize_analytics(threat_analytics),
            "response_coordination_analytics": serialize_analytics(response_analytics),
            "threat_intelligence_analytics": serialize_analytics(intel_analytics),
            "coordination_analytics": serialize_analytics(coord_analytics),
            "system_performance": self.performance_metrics,
            "collaboration_metrics": {
                "total_collaborations": self.system_stats["agent_collaborations"],
                "successful_collaborations": int(self.system_stats["agent_collaborations"] * 0.9),
                "collaboration_success_rate": 0.9
            }
        }

    async def simulate_multi_agent_scenario(self, scenario_type: str) -> Dict[str, Any]:
        """Simulate a multi-agent cybersecurity scenario"""
        scenarios = {
            "advanced_persistent_threat": {
                "threat_data": {
                    "type": "apt_attack",
                    "severity": "critical",
                    "threat_score": 0.95,
                    "indicators": {
                        "sophisticated_malware": True,
                        "long_term_persistence": True,
                        "data_exfiltration": True,
                        "command_control": True
                    }
                }
            },
            "ransomware_campaign": {
                "threat_data": {
                    "type": "ransomware",
                    "severity": "high",
                    "threat_score": 0.85,
                    "indicators": {
                        "encryption_behavior": True,
                        "network_propagation": True,
                        "ransom_note": True
                    }
                }
            },
            "insider_threat": {
                "threat_data": {
                    "type": "insider_threat",
                    "severity": "high",
                    "threat_score": 0.75,
                    "indicators": {
                        "unusual_access_patterns": True,
                        "data_download": True,
                        "off_hours_activity": True
                    }
                }
            }
        }
        
        if scenario_type not in scenarios:
            return {"error": f"Unknown scenario type: {scenario_type}"}
        
        scenario_data = scenarios[scenario_type]
        
        # Run the scenario through the multi-agent system
        result = await self.analyze_threat(scenario_data["threat_data"])
        
        # Add scenario metadata
        result["scenario_metadata"] = {
            "scenario_type": scenario_type,
            "simulation_timestamp": datetime.now().isoformat(),
            "agents_participated": list(self.agents.keys()),
            "coordination_quality": self._assess_collaboration_quality(result)
        }
        
        return result
