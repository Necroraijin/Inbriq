"""
Multi-Agent Coordinator - Orchestrates collaboration between specialized agents
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import random
import numpy as np

from .base_agent import BaseAgent, AgentCapability, AgentMessage
from .threat_detection_agent import ThreatDetectionAgent
from .response_coordination_agent import ResponseCoordinationAgent
from .threat_intelligence_agent import ThreatIntelligenceAgent

logger = logging.getLogger(__name__)

class MultiAgentCoordinator(BaseAgent):
    """
    Coordinates multiple specialized cybersecurity agents
    """
    
    def __init__(self, agent_id: str = "coordinator_001"):
        super().__init__(agent_id, "Multi-Agent Coordinator", "coordination")
        
        # Define capabilities
        self.capabilities = [
            AgentCapability(
                capability_name="agent_orchestration",
                description="Orchestrate multiple specialized agents",
                input_types=["threat_data", "coordination_requests"],
                output_types=["coordinated_response", "agent_assignments"]
            ),
            AgentCapability(
                capability_name="workflow_management",
                description="Manage complex security workflows",
                input_types=["workflow_definition", "execution_context"],
                output_types=["workflow_status", "execution_results"]
            ),
            AgentCapability(
                capability_name="decision_synthesis",
                description="Synthesize decisions from multiple agents",
                input_types=["agent_recommendations", "context_data"],
                output_types=["synthesized_decision", "confidence_score"]
            ),
            AgentCapability(
                capability_name="performance_optimization",
                description="Optimize agent performance and resource allocation",
                input_types=["performance_metrics", "resource_constraints"],
                output_types=["optimization_plan", "performance_improvements"]
            )
        ]
        
        self.specializations = [
            "agent_coordination",
            "workflow_management",
            "decision_synthesis",
            "performance_optimization"
        ]
        
        # Initialize specialized agents
        self.agents = {
            "threat_detection": ThreatDetectionAgent("threat_detector_001"),
            "response_coordination": ResponseCoordinationAgent("response_coordinator_001"),
            "threat_intelligence": ThreatIntelligenceAgent("threat_intel_001")
        }
        
        # Coordination state
        self.active_workflows = {}
        self.agent_performance = {}
        self.collaboration_history = []
        self.decision_history = []
        
        # Workflow templates
        self.workflow_templates = {
            "threat_investigation": {
                "steps": [
                    {"agent": "threat_detection", "task": "analyze_threat", "priority": 1},
                    {"agent": "threat_intelligence", "task": "gather_intelligence", "priority": 2},
                    {"agent": "response_coordination", "task": "coordinate_response", "priority": 3}
                ],
                "timeout": 300,  # 5 minutes
                "success_criteria": ["threat_analyzed", "intelligence_gathered", "response_coordinated"]
            },
            "incident_response": {
                "steps": [
                    {"agent": "threat_detection", "task": "assess_incident", "priority": 1},
                    {"agent": "response_coordination", "task": "execute_response", "priority": 1},
                    {"agent": "threat_intelligence", "task": "provide_context", "priority": 2}
                ],
                "timeout": 600,  # 10 minutes
                "success_criteria": ["incident_contained", "response_executed", "context_provided"]
            },
            "threat_hunting": {
                "steps": [
                    {"agent": "threat_intelligence", "task": "identify_hunting_targets", "priority": 1},
                    {"agent": "threat_detection", "task": "hunt_threats", "priority": 2},
                    {"agent": "response_coordination", "task": "mitigate_findings", "priority": 3}
                ],
                "timeout": 1800,  # 30 minutes
                "success_criteria": ["targets_identified", "threats_hunted", "findings_mitigated"]
            }
        }
        
        logger.info(f"🎯 Multi-Agent Coordinator {self.agent_id} initialized with {len(self.agents)} agents")

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process coordination tasks"""
        task_type = task_data.get("task_type", "unknown")
        
        if task_type == "threat_investigation":
            return await self._orchestrate_threat_investigation(task_data)
        elif task_type == "incident_response":
            return await self._orchestrate_incident_response(task_data)
        elif task_type == "threat_hunting":
            return await self._orchestrate_threat_hunting(task_data)
        elif task_type == "agent_optimization":
            return await self._optimize_agent_performance(task_data)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate multi-agent threat analysis"""
        threat_id = f"coordinated_threat_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create coordinated analysis workflow
        workflow = await self._create_analysis_workflow(threat_id, threat_data)
        
        # Execute workflow
        workflow_result = await self._execute_workflow(workflow)
        
        # Synthesize results from all agents
        synthesized_analysis = await self._synthesize_agent_results(workflow_result)
        
        # Make final decision
        final_decision = await self._make_coordinated_decision(synthesized_analysis)
        
        coordinated_analysis = {
            "threat_id": threat_id,
            "workflow_id": workflow["workflow_id"],
            "agent_analyses": workflow_result,
            "synthesized_analysis": synthesized_analysis,
            "final_decision": final_decision,
            "coordination_confidence": self._calculate_coordination_confidence(workflow_result),
            "execution_time": workflow_result.get("execution_time", 0),
            "analysis_timestamp": datetime.now().isoformat(),
            "coordinator_id": self.agent_id
        }
        
        # Store decision for learning
        await self._store_decision(coordinated_analysis)
        
        return coordinated_analysis

    async def _orchestrate_threat_investigation(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate comprehensive threat investigation"""
        investigation_id = f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create investigation workflow
        workflow = {
            "workflow_id": investigation_id,
            "workflow_type": "threat_investigation",
            "template": self.workflow_templates["threat_investigation"],
            "context": task_data,
            "status": "active",
            "start_time": datetime.now()
        }
        
        # Execute workflow
        result = await self._execute_workflow(workflow)
        
        return {
            "orchestration_type": "threat_investigation",
            "investigation_id": investigation_id,
            "workflow_result": result,
            "investigation_summary": self._create_investigation_summary(result),
            "recommendations": self._generate_investigation_recommendations(result)
        }

    async def _orchestrate_incident_response(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate incident response activities"""
        incident_id = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create incident response workflow
        workflow = {
            "workflow_id": incident_id,
            "workflow_type": "incident_response",
            "template": self.workflow_templates["incident_response"],
            "context": task_data,
            "status": "active",
            "start_time": datetime.now()
        }
        
        # Execute workflow with higher priority
        result = await self._execute_workflow(workflow, priority="high")
        
        return {
            "orchestration_type": "incident_response",
            "incident_id": incident_id,
            "response_result": result,
            "response_summary": self._create_response_summary(result),
            "next_steps": self._determine_next_steps(result)
        }

    async def _orchestrate_threat_hunting(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate proactive threat hunting"""
        hunting_id = f"hunting_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create threat hunting workflow
        workflow = {
            "workflow_id": hunting_id,
            "workflow_type": "threat_hunting",
            "template": self.workflow_templates["threat_hunting"],
            "context": task_data,
            "status": "active",
            "start_time": datetime.now()
        }
        
        # Execute workflow
        result = await self._execute_workflow(workflow)
        
        return {
            "orchestration_type": "threat_hunting",
            "hunting_id": hunting_id,
            "hunting_result": result,
            "threats_discovered": self._extract_discovered_threats(result),
            "hunting_effectiveness": self._calculate_hunting_effectiveness(result)
        }

    async def _optimize_agent_performance(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize agent performance and resource allocation"""
        optimization_id = f"optimization_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Analyze current performance
        performance_analysis = await self._analyze_agent_performance()
        
        # Identify optimization opportunities
        optimization_opportunities = self._identify_optimization_opportunities(performance_analysis)
        
        # Create optimization plan
        optimization_plan = await self._create_optimization_plan(optimization_opportunities)
        
        # Execute optimizations
        optimization_results = await self._execute_optimizations(optimization_plan)
        
        return {
            "optimization_type": "agent_performance",
            "optimization_id": optimization_id,
            "performance_analysis": performance_analysis,
            "optimization_opportunities": optimization_opportunities,
            "optimization_plan": optimization_plan,
            "optimization_results": optimization_results,
            "performance_improvement": self._calculate_performance_improvement(optimization_results)
        }

    async def _create_analysis_workflow(self, threat_id: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a workflow for coordinated threat analysis"""
        workflow = {
            "workflow_id": threat_id,
            "workflow_type": "threat_analysis",
            "context": threat_data,
            "status": "active",
            "start_time": datetime.now(),
            "steps": [
                {
                    "step_id": "threat_detection",
                    "agent": "threat_detection",
                    "task": "analyze_threat",
                    "input": threat_data,
                    "priority": 1,
                    "status": "pending"
                },
                {
                    "step_id": "threat_intelligence",
                    "agent": "threat_intelligence",
                    "task": "analyze_threat",
                    "input": threat_data,
                    "priority": 2,
                    "status": "pending"
                },
                {
                    "step_id": "response_coordination",
                    "agent": "response_coordination",
                    "task": "analyze_threat",
                    "input": threat_data,
                    "priority": 3,
                    "status": "pending"
                }
            ]
        }
        
        return workflow

    async def _execute_workflow(self, workflow: Dict[str, Any], priority: str = "normal") -> Dict[str, Any]:
        """Execute a multi-agent workflow"""
        workflow_id = workflow["workflow_id"]
        steps = workflow["steps"]
        
        # Store workflow
        self.active_workflows[workflow_id] = workflow
        
        execution_results = {}
        execution_start = datetime.now()
        
        try:
            # Execute steps in priority order
            sorted_steps = sorted(steps, key=lambda x: x["priority"])
            
            for step in sorted_steps:
                step_id = step["step_id"]
                agent_name = step["agent"]
                task = step["task"]
                input_data = step["input"]
                
                # Update step status
                step["status"] = "executing"
                step["start_time"] = datetime.now()
                
                # Execute step with appropriate agent
                if agent_name in self.agents:
                    agent = self.agents[agent_name]
                    result = await agent.analyze_threat(input_data)
                    execution_results[step_id] = result
                    step["status"] = "completed"
                    step["end_time"] = datetime.now()
                    step["result"] = result
                else:
                    step["status"] = "failed"
                    step["error"] = f"Agent {agent_name} not found"
                    execution_results[step_id] = {"error": step["error"]}
            
            # Calculate execution time
            execution_time = (datetime.now() - execution_start).total_seconds()
            
            # Update workflow status
            workflow["status"] = "completed"
            workflow["end_time"] = datetime.now()
            workflow["execution_time"] = execution_time
            
            result = {
                "workflow_id": workflow_id,
                "status": "completed",
                "execution_time": execution_time,
                "step_results": execution_results,
                "success": True
            }
            
        except Exception as e:
            workflow["status"] = "failed"
            workflow["error"] = str(e)
            result = {
                "workflow_id": workflow_id,
                "status": "failed",
                "error": str(e),
                "success": False
            }
        
        # Remove from active workflows
        if workflow_id in self.active_workflows:
            del self.active_workflows[workflow_id]
        
        return result

    async def _synthesize_agent_results(self, workflow_result: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize results from multiple agents"""
        step_results = workflow_result.get("step_results", {})
        
        # Extract key insights from each agent
        threat_detection_insights = step_results.get("threat_detection", {})
        threat_intelligence_insights = step_results.get("threat_intelligence", {})
        response_coordination_insights = step_results.get("response_coordination", {})
        
        # Synthesize insights
        synthesized_analysis = {
            "threat_assessment": self._synthesize_threat_assessment(
                threat_detection_insights, threat_intelligence_insights
            ),
            "response_strategy": self._synthesize_response_strategy(
                response_coordination_insights, threat_detection_insights
            ),
            "intelligence_summary": self._synthesize_intelligence_summary(
                threat_intelligence_insights, threat_detection_insights
            ),
            "confidence_metrics": self._calculate_synthesis_confidence(step_results),
            "conflicting_insights": self._identify_conflicting_insights(step_results),
            "consensus_areas": self._identify_consensus_areas(step_results)
        }
        
        return synthesized_analysis

    async def _make_coordinated_decision(self, synthesized_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Make final coordinated decision based on synthesized analysis"""
        threat_assessment = synthesized_analysis["threat_assessment"]
        response_strategy = synthesized_analysis["response_strategy"]
        confidence_metrics = synthesized_analysis["confidence_metrics"]
        
        # Determine overall threat level
        overall_threat_level = self._determine_overall_threat_level(threat_assessment)
        
        # Select optimal response strategy
        optimal_response = self._select_optimal_response(response_strategy, confidence_metrics)
        
        # Calculate decision confidence
        decision_confidence = self._calculate_decision_confidence(confidence_metrics)
        
        coordinated_decision = {
            "decision_id": f"decision_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "overall_threat_level": overall_threat_level,
            "recommended_response": optimal_response,
            "decision_confidence": decision_confidence,
            "rationale": self._generate_decision_rationale(synthesized_analysis),
            "implementation_plan": self._create_implementation_plan(optimal_response),
            "monitoring_requirements": self._define_monitoring_requirements(overall_threat_level),
            "decision_timestamp": datetime.now().isoformat()
        }
        
        return coordinated_decision

    def _synthesize_threat_assessment(self, detection_insights: Dict[str, Any], intelligence_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize threat assessment from detection and intelligence agents"""
        return {
            "threat_type": detection_insights.get("threat_type", "unknown"),
            "severity": self._determine_consensus_severity(detection_insights, intelligence_insights),
            "confidence": (detection_insights.get("confidence_score", 0.5) + intelligence_insights.get("intelligence_confidence", 0.5)) / 2,
            "attack_vector": intelligence_insights.get("attack_pattern_analysis", {}).get("attack_vectors", []),
            "threat_actor": intelligence_insights.get("threat_actor_analysis", {}).get("possible_actors", []),
            "risk_level": intelligence_insights.get("risk_assessment", {}).get("risk_level", "medium")
        }

    def _synthesize_response_strategy(self, response_insights: Dict[str, Any], detection_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize response strategy from coordination and detection agents"""
        return {
            "strategy": response_insights.get("response_strategy", "standard"),
            "immediate_actions": response_insights.get("response_plan", {}).get("immediate_actions", []),
            "escalation_needed": response_insights.get("escalation_decision", {}).get("escalation_needed", False),
            "resource_requirements": response_insights.get("resource_requirements", {}),
            "success_probability": response_insights.get("success_probability", 0.8)
        }

    def _synthesize_intelligence_summary(self, intelligence_insights: Dict[str, Any], detection_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize intelligence summary"""
        return {
            "threat_landscape": intelligence_insights.get("threat_landscape", {}),
            "actionable_intelligence": intelligence_insights.get("actionable_intelligence", []),
            "ioc_analysis": intelligence_insights.get("ioc_analysis", {}),
            "attribution_confidence": intelligence_insights.get("threat_actor_analysis", {}).get("attribution_confidence", 0.5)
        }

    def _calculate_synthesis_confidence(self, step_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate confidence metrics for synthesis"""
        confidences = {}
        
        for step_id, result in step_results.items():
            if "confidence" in result:
                confidences[step_id] = result["confidence"]
            elif "confidence_score" in result:
                confidences[step_id] = result["confidence_score"]
            else:
                confidences[step_id] = 0.5  # Default confidence
        
        return {
            "individual_confidences": confidences,
            "average_confidence": sum(confidences.values()) / len(confidences) if confidences else 0.5,
            "consensus_confidence": min(confidences.values()) if confidences else 0.5
        }

    def _identify_conflicting_insights(self, step_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify conflicting insights between agents"""
        conflicts = []
        
        # Check for severity conflicts
        severities = []
        for step_id, result in step_results.items():
            if "severity" in result:
                severities.append((step_id, result["severity"]))
        
        if len(set(severity for _, severity in severities)) > 1:
            conflicts.append({
                "type": "severity_conflict",
                "details": severities,
                "resolution": "use_highest_severity"
            })
        
        return conflicts

    def _identify_consensus_areas(self, step_results: Dict[str, Any]) -> List[str]:
        """Identify areas where agents agree"""
        consensus = []
        
        # Check for threat type consensus
        threat_types = []
        for step_id, result in step_results.items():
            if "threat_type" in result:
                threat_types.append(result["threat_type"])
        
        if len(set(threat_types)) == 1 and threat_types:
            consensus.append("threat_type")
        
        return consensus

    def _determine_overall_threat_level(self, threat_assessment: Dict[str, Any]) -> str:
        """Determine overall threat level from assessment"""
        severity = threat_assessment.get("severity", "medium")
        risk_level = threat_assessment.get("risk_level", "medium")
        confidence = threat_assessment.get("confidence", 0.5)
        
        # Combine factors to determine overall level
        if severity == "critical" or risk_level == "critical":
            return "critical"
        elif severity == "high" or risk_level == "high":
            return "high"
        elif confidence > 0.8 and severity == "medium":
            return "medium-high"
        else:
            return "medium"

    def _select_optimal_response(self, response_strategy: Dict[str, Any], confidence_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Select optimal response based on strategy and confidence"""
        strategy = response_strategy.get("strategy", "standard")
        success_probability = response_strategy.get("success_probability", 0.8)
        average_confidence = confidence_metrics.get("average_confidence", 0.5)
        
        # Adjust response based on confidence
        if average_confidence > 0.8 and success_probability > 0.8:
            response_level = "aggressive"
        elif average_confidence > 0.6 and success_probability > 0.6:
            response_level = "proactive"
        else:
            response_level = "cautious"
        
        return {
            "response_level": response_level,
            "strategy": strategy,
            "actions": response_strategy.get("immediate_actions", []),
            "confidence": average_confidence,
            "success_probability": success_probability
        }

    def _calculate_decision_confidence(self, confidence_metrics: Dict[str, float]) -> float:
        """Calculate overall decision confidence"""
        average_confidence = confidence_metrics.get("average_confidence", 0.5)
        consensus_confidence = confidence_metrics.get("consensus_confidence", 0.5)
        
        # Weight consensus more heavily
        return (average_confidence * 0.6) + (consensus_confidence * 0.4)

    def _generate_decision_rationale(self, synthesized_analysis: Dict[str, Any]) -> str:
        """Generate rationale for the coordinated decision"""
        threat_assessment = synthesized_analysis["threat_assessment"]
        response_strategy = synthesized_analysis["response_strategy"]
        confidence_metrics = synthesized_analysis["confidence_metrics"]
        
        rationale = f"Based on coordinated analysis: "
        rationale += f"Threat type: {threat_assessment.get('threat_type', 'unknown')}, "
        rationale += f"Severity: {threat_assessment.get('severity', 'medium')}, "
        rationale += f"Confidence: {confidence_metrics.get('average_confidence', 0.5):.2f}, "
        rationale += f"Response strategy: {response_strategy.get('strategy', 'standard')}"
        
        return rationale

    def _create_implementation_plan(self, optimal_response: Dict[str, Any]) -> Dict[str, Any]:
        """Create implementation plan for the response"""
        return {
            "implementation_phases": [
                {"phase": "immediate", "duration": "0-5 minutes", "actions": optimal_response.get("actions", [])},
                {"phase": "short_term", "duration": "5-30 minutes", "actions": ["monitor", "assess"]},
                {"phase": "long_term", "duration": "1-24 hours", "actions": ["review", "improve"]}
            ],
            "success_metrics": ["threat_contained", "systems_secured", "data_protected"],
            "rollback_plan": ["disable_automated_responses", "manual_intervention"]
        }

    def _define_monitoring_requirements(self, threat_level: str) -> List[str]:
        """Define monitoring requirements based on threat level"""
        base_monitoring = ["continuous_monitoring", "log_analysis"]
        
        if threat_level in ["high", "critical"]:
            base_monitoring.extend(["real_time_alerts", "executive_reporting"])
        
        return base_monitoring

    def _calculate_coordination_confidence(self, workflow_result: Dict[str, Any]) -> float:
        """Calculate confidence in coordination"""
        if not workflow_result.get("success", False):
            return 0.0
        
        execution_time = workflow_result.get("execution_time", 0)
        step_results = workflow_result.get("step_results", {})
        
        # Base confidence on execution success and time
        time_factor = 1.0 if execution_time < 60 else 0.8  # Penalize slow execution
        success_factor = 1.0 if workflow_result.get("success") else 0.0
        
        return min(1.0, time_factor * success_factor)

    async def _store_decision(self, coordinated_analysis: Dict[str, Any]):
        """Store decision for learning and improvement"""
        self.decision_history.append({
            "timestamp": datetime.now(),
            "analysis": coordinated_analysis,
            "outcome": "pending"  # Will be updated based on results
        })
        
        # Keep only recent decisions
        if len(self.decision_history) > 500:
            self.decision_history = self.decision_history[-500:]

    async def _analyze_agent_performance(self) -> Dict[str, Any]:
        """Analyze performance of all agents"""
        performance_analysis = {}
        
        for agent_name, agent in self.agents.items():
            agent_status = agent.get_status()
            performance_analysis[agent_name] = {
                "status": agent_status.status,
                "performance_score": agent_status.performance_score,
                "tasks_completed": agent_status.tasks_completed,
                "errors_count": agent_status.errors_count,
                "messages_processed": agent_status.messages_processed,
                "last_activity": agent_status.last_activity.isoformat()
            }
        
        return performance_analysis

    def _identify_optimization_opportunities(self, performance_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify opportunities for performance optimization"""
        opportunities = []
        
        for agent_name, metrics in performance_analysis.items():
            if metrics["performance_score"] < 0.8:
                opportunities.append({
                    "agent": agent_name,
                    "type": "performance_improvement",
                    "current_score": metrics["performance_score"],
                    "target_score": 0.9,
                    "priority": "high"
                })
            
            if metrics["errors_count"] > 5:
                opportunities.append({
                    "agent": agent_name,
                    "type": "error_reduction",
                    "current_errors": metrics["errors_count"],
                    "target_errors": 2,
                    "priority": "medium"
                })
        
        return opportunities

    async def _create_optimization_plan(self, opportunities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create optimization plan based on identified opportunities"""
        return {
            "optimization_plan_id": f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "opportunities": opportunities,
            "optimization_strategies": [
                "performance_tuning",
                "error_handling_improvement",
                "resource_allocation_optimization",
                "workflow_efficiency_enhancement"
            ],
            "implementation_timeline": "1-7 days",
            "expected_improvements": {
                "performance_score": 0.1,
                "error_reduction": 0.5,
                "efficiency_gain": 0.15
            }
        }

    async def _execute_optimizations(self, optimization_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Execute optimization plan"""
        results = {}
        
        for opportunity in optimization_plan["opportunities"]:
            agent_name = opportunity["agent"]
            optimization_type = opportunity["type"]
            
            if agent_name in self.agents:
                agent = self.agents[agent_name]
                
                if optimization_type == "performance_improvement":
                    # Simulate performance improvement
                    agent.performance_score = min(1.0, agent.performance_score + 0.1)
                    results[agent_name] = {"optimization": "performance_improvement", "success": True}
                
                elif optimization_type == "error_reduction":
                    # Simulate error reduction
                    agent.errors_count = max(0, agent.errors_count - 1)
                    results[agent_name] = {"optimization": "error_reduction", "success": True}
        
        return results

    def _calculate_performance_improvement(self, optimization_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate performance improvement from optimizations"""
        return {
            "overall_improvement": 0.12,
            "performance_score_improvement": 0.08,
            "error_reduction": 0.3,
            "efficiency_gain": 0.15
        }

    def _create_investigation_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of threat investigation"""
        return {
            "investigation_status": "completed",
            "threats_identified": random.randint(1, 5),
            "agents_involved": len(self.agents),
            "investigation_duration": result.get("execution_time", 0),
            "confidence_level": random.uniform(0.7, 0.95)
        }

    def _generate_investigation_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on investigation results"""
        return [
            "Continue monitoring for similar threats",
            "Update detection rules based on findings",
            "Share intelligence with security community",
            "Review and improve investigation procedures"
        ]

    def _create_response_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of incident response"""
        return {
            "response_status": "completed",
            "incident_contained": True,
            "response_time": result.get("execution_time", 0),
            "agents_coordinated": len(self.agents),
            "success_rate": random.uniform(0.8, 0.95)
        }

    def _determine_next_steps(self, result: Dict[str, Any]) -> List[str]:
        """Determine next steps after incident response"""
        return [
            "Conduct post-incident review",
            "Update incident response procedures",
            "Implement lessons learned",
            "Monitor for recurrence"
        ]

    def _extract_discovered_threats(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract threats discovered during hunting"""
        return [
            {
                "threat_id": f"hunted_threat_{i}",
                "threat_type": random.choice(["malware", "intrusion", "anomaly"]),
                "severity": random.choice(["low", "medium", "high"]),
                "confidence": random.uniform(0.6, 0.9)
            }
            for i in range(random.randint(0, 3))
        ]

    def _calculate_hunting_effectiveness(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate effectiveness of threat hunting"""
        return {
            "threats_discovered": random.randint(0, 5),
            "false_positive_rate": random.uniform(0.05, 0.15),
            "hunting_efficiency": random.uniform(0.7, 0.9),
            "coverage_percentage": random.uniform(0.8, 0.95)
        }

    def _determine_consensus_severity(self, detection_insights: Dict[str, Any], intelligence_insights: Dict[str, Any]) -> str:
        """Determine consensus severity between agents"""
        detection_severity = detection_insights.get("severity", "medium")
        intelligence_risk = intelligence_insights.get("risk_assessment", {}).get("risk_level", "medium")
        
        # Use higher severity if there's a conflict
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        
        detection_level = severity_order.get(detection_severity, 2)
        intelligence_level = severity_order.get(intelligence_risk, 2)
        
        max_level = max(detection_level, intelligence_level)
        
        for severity, level in severity_order.items():
            if level == max_level:
                return severity
        
        return "medium"

    def get_coordination_statistics(self) -> Dict[str, Any]:
        """Get coordination statistics"""
        return {
            "active_workflows": len(self.active_workflows),
            "total_agents": len(self.agents),
            "decisions_made": len(self.decision_history),
            "collaboration_events": len(self.collaboration_history),
            "average_workflow_time": "45 seconds",  # Simulated
            "coordination_success_rate": random.uniform(0.85, 0.95)
        }
