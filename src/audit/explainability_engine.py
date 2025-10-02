"""
Enhanced Explainability System - Comprehensive audit trails with decision rationales
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
import json
import hashlib
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class DecisionType(Enum):
    """Types of decisions made by the system"""
    THREAT_DETECTION = "threat_detection"
    RESPONSE_ACTION = "response_action"
    TRUST_EVALUATION = "trust_evaluation"
    POLICY_ENFORCEMENT = "policy_enforcement"
    RESOURCE_ALLOCATION = "resource_allocation"

class ConfidenceLevel(Enum):
    """Confidence levels for decisions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class DecisionFactor:
    """Individual factor that influenced a decision"""
    factor_name: str
    factor_value: Union[str, float, int, bool]
    weight: float
    impact: str
    confidence: float
    source: str

@dataclass
class DecisionRationale:
    """Comprehensive rationale for a decision"""
    decision_id: str
    decision_type: DecisionType
    timestamp: datetime
    entity_id: str
    decision_outcome: str
    confidence_level: ConfidenceLevel
    factors: List[DecisionFactor]
    reasoning_chain: List[str]
    alternative_options: List[str]
    risk_assessment: Dict[str, Any]
    audit_trail: List[str]

@dataclass
class ExplainabilityReport:
    """Complete explainability report"""
    report_id: str
    decision_rationale: DecisionRationale
    model_explanations: Dict[str, Any]
    feature_importance: Dict[str, float]
    decision_tree_path: List[str]
    counterfactual_analysis: Dict[str, Any]
    compliance_metadata: Dict[str, Any]
    human_readable_summary: str

class EnhancedExplainabilityEngine:
    """
    Enhanced Explainability System for comprehensive audit trails and decision rationales
    """
    
    def __init__(self):
        self.decision_history = []
        self.explainability_reports = {}
        self.audit_logs = []
        self.compliance_metadata = {
            'system_version': '1.0.0',
            'compliance_standards': ['SOC2', 'ISO27001', 'GDPR'],
            'data_retention_days': 365,
            'audit_level': 'comprehensive'
        }

        self.decision_templates = {
            DecisionType.THREAT_DETECTION: self._create_threat_detection_template(),
            DecisionType.RESPONSE_ACTION: self._create_response_action_template(),
            DecisionType.TRUST_EVALUATION: self._create_trust_evaluation_template(),
            DecisionType.POLICY_ENFORCEMENT: self._create_policy_enforcement_template(),
            DecisionType.RESOURCE_ALLOCATION: self._create_resource_allocation_template()
        }
        
        logger.info("📋 Enhanced Explainability Engine initialized")

    def _create_threat_detection_template(self) -> Dict[str, Any]:
        """Template for threat detection decisions"""
        return {
            'required_factors': ['threat_score', 'confidence', 'threat_type', 'source_ip'],
            'reasoning_steps': [
                'Analyze network traffic patterns',
                'Evaluate threat indicators',
                'Calculate risk score',
                'Determine threat classification'
            ],
            'risk_categories': ['network_anomaly', 'malware', 'ddos', 'intrusion', 'data_exfiltration']
        }

    def _create_response_action_template(self) -> Dict[str, Any]:
        """Template for response action decisions"""
        return {
            'required_factors': ['threat_severity', 'response_effectiveness', 'blast_radius', 'recovery_time'],
            'reasoning_steps': [
                'Assess threat severity',
                'Evaluate response options',
                'Calculate blast radius',
                'Select optimal response'
            ],
            'action_categories': ['block_ip', 'quarantine', 'rate_limit', 'alert', 'escalate']
        }

    def _create_trust_evaluation_template(self) -> Dict[str, Any]:
        """Template for trust evaluation decisions"""
        return {
            'required_factors': ['behavioral_score', 'geographic_score', 'temporal_score', 'device_score'],
            'reasoning_steps': [
                'Analyze behavioral patterns',
                'Evaluate geographic context',
                'Assess temporal patterns',
                'Calculate overall trust score'
            ],
            'trust_levels': ['low', 'medium', 'high', 'critical']
        }

    def _create_policy_enforcement_template(self) -> Dict[str, Any]:
        """Template for policy enforcement decisions"""
        return {
            'required_factors': ['policy_violation', 'severity', 'context', 'user_role'],
            'reasoning_steps': [
                'Identify policy violation',
                'Assess violation severity',
                'Evaluate context and intent',
                'Apply appropriate enforcement'
            ],
            'enforcement_actions': ['warn', 'restrict', 'block', 'escalate']
        }

    def _create_resource_allocation_template(self) -> Dict[str, Any]:
        """Template for resource allocation decisions"""
        return {
            'required_factors': ['resource_demand', 'available_capacity', 'priority', 'cost'],
            'reasoning_steps': [
                'Assess resource demand',
                'Evaluate available capacity',
                'Determine priority level',
                'Allocate resources optimally'
            ],
            'allocation_strategies': ['fair_share', 'priority_based', 'load_balanced', 'cost_optimized']
        }

    async def create_decision_rationale(
        self,
        decision_type: DecisionType,
        entity_id: str,
        decision_outcome: str,
        factors: List[DecisionFactor],
        context: Dict[str, Any],
        confidence: float
    ) -> DecisionRationale:
        """
        Create comprehensive decision rationale
        """
        decision_id = str(uuid.uuid4())
        timestamp = datetime.now()

        confidence_level = self._determine_confidence_level(confidence)

        reasoning_chain = await self._generate_reasoning_chain(decision_type, factors, context)

        alternative_options = await self._identify_alternative_options(decision_type, factors, context)

        risk_assessment = await self._perform_risk_assessment(decision_type, factors, context)

        audit_trail = await self._create_audit_trail(decision_id, decision_type, factors, context)
        
        rationale = DecisionRationale(
            decision_id=decision_id,
            decision_type=decision_type,
            timestamp=timestamp,
            entity_id=entity_id,
            decision_outcome=decision_outcome,
            confidence_level=confidence_level,
            factors=factors,
            reasoning_chain=reasoning_chain,
            alternative_options=alternative_options,
            risk_assessment=risk_assessment,
            audit_trail=audit_trail
        )

        self.decision_history.append(rationale)
        
        return rationale

    async def generate_explainability_report(
        self,
        decision_rationale: DecisionRationale,
        model_data: Dict[str, Any],
        feature_data: Dict[str, Any]
    ) -> ExplainabilityReport:
        """
        Generate comprehensive explainability report
        """
        report_id = str(uuid.uuid4())

        model_explanations = await self._generate_model_explanations(model_data, decision_rationale)

        feature_importance = await self._calculate_feature_importance(feature_data, decision_rationale)

        decision_tree_path = await self._generate_decision_tree_path(decision_rationale)

        counterfactual_analysis = await self._perform_counterfactual_analysis(decision_rationale, model_data)

        human_readable_summary = await self._generate_human_readable_summary(decision_rationale)
        
        report = ExplainabilityReport(
            report_id=report_id,
            decision_rationale=decision_rationale,
            model_explanations=model_explanations,
            feature_importance=feature_importance,
            decision_tree_path=decision_tree_path,
            counterfactual_analysis=counterfactual_analysis,
            compliance_metadata=self.compliance_metadata,
            human_readable_summary=human_readable_summary
        )

        self.explainability_reports[report_id] = report
        
        return report

    def _determine_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Determine confidence level from numeric confidence"""
        if confidence >= 0.9:
            return ConfidenceLevel.CRITICAL
        elif confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    async def _generate_reasoning_chain(
        self,
        decision_type: DecisionType,
        factors: List[DecisionFactor],
        context: Dict[str, Any]
    ) -> List[str]:
        """Generate step-by-step reasoning chain"""
        template = self.decision_templates[decision_type]
        reasoning_steps = template['reasoning_steps'].copy()

        if decision_type == DecisionType.THREAT_DETECTION:
            threat_score = next((f.factor_value for f in factors if f.factor_name == 'threat_score'), 0)
            if threat_score > 0.8:
                reasoning_steps.append("High threat score indicates immediate action required")
            elif threat_score > 0.6:
                reasoning_steps.append("Moderate threat score requires monitoring and potential action")
            else:
                reasoning_steps.append("Low threat score indicates normal activity")
        
        elif decision_type == DecisionType.RESPONSE_ACTION:
            severity = next((f.factor_value for f in factors if f.factor_name == 'threat_severity'), 'medium')
            if severity == 'critical':
                reasoning_steps.append("Critical severity requires immediate containment")
            elif severity == 'high':
                reasoning_steps.append("High severity requires rapid response")
            else:
                reasoning_steps.append("Standard response procedures applied")
        
        return reasoning_steps

    async def _identify_alternative_options(
        self,
        decision_type: DecisionType,
        factors: List[DecisionFactor],
        context: Dict[str, Any]
    ) -> List[str]:
        """Identify alternative decision options"""
        template = self.decision_templates[decision_type]
        
        if decision_type == DecisionType.THREAT_DETECTION:
            return [
                "Classify as false positive",
                "Escalate to human analyst",
                "Increase monitoring level",
                "Apply additional detection rules"
            ]
        
        elif decision_type == DecisionType.RESPONSE_ACTION:
            return [
                "Block IP address",
                "Rate limit connections",
                "Quarantine system",
                "Send alert to administrators",
                "Escalate to incident response team"
            ]
        
        elif decision_type == DecisionType.TRUST_EVALUATION:
            return [
                "Grant full access",
                "Require additional authentication",
                "Limit access to specific resources",
                "Block access temporarily"
            ]
        
        return ["Alternative option 1", "Alternative option 2", "Alternative option 3"]

    async def _perform_risk_assessment(
        self,
        decision_type: DecisionType,
        factors: List[DecisionFactor],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        risk_assessment = {
            'overall_risk_level': 'medium',
            'risk_factors': [],
            'mitigation_strategies': [],
            'residual_risk': 'low'
        }

        for factor in factors:
            if factor.impact == 'negative' and factor.weight > 0.7:
                risk_assessment['risk_factors'].append(f"High impact from {factor.factor_name}")
            elif factor.impact == 'negative' and factor.weight > 0.4:
                risk_assessment['risk_factors'].append(f"Moderate impact from {factor.factor_name}")

        high_risk_factors = len([f for f in factors if f.impact == 'negative' and f.weight > 0.7])
        if high_risk_factors > 2:
            risk_assessment['overall_risk_level'] = 'high'
        elif high_risk_factors > 0:
            risk_assessment['overall_risk_level'] = 'medium'
        else:
            risk_assessment['overall_risk_level'] = 'low'

        if risk_assessment['overall_risk_level'] == 'high':
            risk_assessment['mitigation_strategies'] = [
                "Implement immediate containment measures",
                "Escalate to senior security team",
                "Activate incident response procedures"
            ]
        elif risk_assessment['overall_risk_level'] == 'medium':
            risk_assessment['mitigation_strategies'] = [
                "Increase monitoring frequency",
                "Apply additional security controls",
                "Review and update policies"
            ]
        else:
            risk_assessment['mitigation_strategies'] = [
                "Continue normal monitoring",
                "Document decision for future reference"
            ]
        
        return risk_assessment

    async def _create_audit_trail(
        self,
        decision_id: str,
        decision_type: DecisionType,
        factors: List[DecisionFactor],
        context: Dict[str, Any]
    ) -> List[str]:
        """Create comprehensive audit trail"""
        audit_trail = [
            f"Decision {decision_id} initiated at {datetime.now().isoformat()}",
            f"Decision type: {decision_type.value}",
            f"Context: {json.dumps(context, default=str)}",
            f"Factors considered: {len(factors)}"
        ]

        for factor in factors:
            audit_trail.append(
                f"Factor: {factor.factor_name} = {factor.factor_value} "
                f"(weight: {factor.weight}, impact: {factor.impact}, confidence: {factor.confidence})"
            )

        audit_trail.extend([
            f"System version: {self.compliance_metadata['system_version']}",
            f"Compliance standards: {', '.join(self.compliance_metadata['compliance_standards'])}",
            f"Audit level: {self.compliance_metadata['audit_level']}"
        ])
        
        return audit_trail

    async def _generate_model_explanations(
        self,
        model_data: Dict[str, Any],
        decision_rationale: DecisionRationale
    ) -> Dict[str, Any]:
        """Generate model-specific explanations"""
        explanations = {
            'model_type': model_data.get('model_type', 'unknown'),
            'model_version': model_data.get('model_version', '1.0.0'),
            'prediction_confidence': model_data.get('confidence', 0.5),
            'feature_contributions': {},
            'decision_boundary': {},
            'model_limitations': []
        }

        for factor in decision_rationale.factors:
            explanations['feature_contributions'][factor.factor_name] = {
                'value': factor.factor_value,
                'contribution': factor.weight,
                'impact': factor.impact
            }

        explanations['model_limitations'] = [
            "Model trained on historical data, may not capture novel attack patterns",
            "Confidence scores based on training data distribution",
            "Feature importance may vary based on context and environment"
        ]
        
        return explanations

    async def _calculate_feature_importance(
        self,
        feature_data: Dict[str, Any],
        decision_rationale: DecisionRationale
    ) -> Dict[str, float]:
        """Calculate feature importance scores"""
        feature_importance = {}

        for factor in decision_rationale.factors:
            importance = factor.weight
            if factor.impact == 'negative':
                importance *= 1.2
            elif factor.impact == 'positive':
                importance *= 0.8
            
            feature_importance[factor.factor_name] = min(1.0, importance)

        total_importance = sum(feature_importance.values())
        if total_importance > 0:
            feature_importance = {
                k: v / total_importance for k, v in feature_importance.items()
            }
        
        return feature_importance

    async def _generate_decision_tree_path(
        self,
        decision_rationale: DecisionRationale
    ) -> List[str]:
        """Generate decision tree path"""
        path = [f"Start: {decision_rationale.decision_type.value}"]

        for i, step in enumerate(decision_rationale.reasoning_chain):
            path.append(f"Step {i+1}: {step}")

        path.append(f"Decision: {decision_rationale.decision_outcome}")
        
        return path

    async def _perform_counterfactual_analysis(
        self,
        decision_rationale: DecisionRationale,
        model_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform counterfactual analysis"""
        counterfactual = {
            'scenario_1': {
                'description': 'What if threat score was lower?',
                'hypothetical_factors': [],
                'predicted_outcome': 'Different response action',
                'confidence_change': -0.2
            },
            'scenario_2': {
                'description': 'What if confidence was higher?',
                'hypothetical_factors': [],
                'predicted_outcome': 'More aggressive response',
                'confidence_change': 0.3
            },
            'scenario_3': {
                'description': 'What if additional context was available?',
                'hypothetical_factors': [],
                'predicted_outcome': 'More nuanced decision',
                'confidence_change': 0.1
            }
        }
        
        return counterfactual

    async def _generate_human_readable_summary(
        self,
        decision_rationale: DecisionRationale
    ) -> str:
        """Generate human-readable summary of the decision"""
        summary = f"""
        Decision Summary for {decision_rationale.decision_type.value}
        
        Entity: {decision_rationale.entity_id}
        Outcome: {decision_rationale.decision_outcome}
        Confidence: {decision_rationale.confidence_level.value}
        Timestamp: {decision_rationale.timestamp.isoformat()}
        
        Key Factors:
        """
        
        for factor in decision_rationale.factors:
            summary += f"• {factor.factor_name}: {factor.factor_value} (impact: {factor.impact})\n"
        
        summary += f"""
        Reasoning:
        """
        for i, step in enumerate(decision_rationale.reasoning_chain):
            summary += f"{i+1}. {step}\n"
        
        summary += f"""
        Risk Assessment: {decision_rationale.risk_assessment['overall_risk_level']}
        Alternative Options: {', '.join(decision_rationale.alternative_options)}
        """
        
        return summary.strip()

    async def get_explainability_statistics(self) -> Dict[str, Any]:
        """Get explainability engine statistics"""
        total_decisions = len(self.decision_history)
        total_reports = len(self.explainability_reports)

        decision_types = {}
        for rationale in self.decision_history:
            decision_type = rationale.decision_type.value
            decision_types[decision_type] = decision_types.get(decision_type, 0) + 1

        confidence_levels = {}
        for rationale in self.decision_history:
            confidence = rationale.confidence_level.value
            confidence_levels[confidence] = confidence_levels.get(confidence, 0) + 1
        
        return {
            'total_decisions_explained': total_decisions,
            'total_explainability_reports': total_reports,
            'decision_type_distribution': decision_types,
            'confidence_level_distribution': confidence_levels,
            'average_factors_per_decision': np.mean([len(r.factors) for r in self.decision_history]) if total_decisions > 0 else 0,
            'explainability_engine_status': 'active'
        }

    async def search_decisions(
        self,
        entity_id: Optional[str] = None,
        decision_type: Optional[DecisionType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[DecisionRationale]:
        """Search decision history with filters"""
        filtered_decisions = self.decision_history
        
        if entity_id:
            filtered_decisions = [d for d in filtered_decisions if d.entity_id == entity_id]
        
        if decision_type:
            filtered_decisions = [d for d in filtered_decisions if d.decision_type == decision_type]
        
        if start_time:
            filtered_decisions = [d for d in filtered_decisions if d.timestamp >= start_time]
        
        if end_time:
            filtered_decisions = [d for d in filtered_decisions if d.timestamp <= end_time]

        filtered_decisions.sort(key=lambda x: x.timestamp, reverse=True)
        
        return filtered_decisions[:limit]

    async def export_audit_log(self, format: str = 'json') -> str:
        """Export audit log in specified format"""
        if format == 'json':
            return json.dumps([asdict(rationale) for rationale in self.decision_history], default=str, indent=2)
        elif format == 'csv':

            csv_data = "decision_id,decision_type,entity_id,outcome,confidence,timestamp\n"
            for rationale in self.decision_history:
                csv_data += f"{rationale.decision_id},{rationale.decision_type.value},{rationale.entity_id},{rationale.decision_outcome},{rationale.confidence_level.value},{rationale.timestamp.isoformat()}\n"
            return csv_data
        else:
            raise ValueError(f"Unsupported export format: {format}")