"""
Continuous Trust Scoring Engine - Real-time multi-factor trust evaluation
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import numpy as np
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)

@dataclass
class TrustFactors:
    """Trust factor weights for scoring"""
    behavioral: float = 0.4
    geographic: float = 0.2
    temporal: float = 0.2
    device: float = 0.2

@dataclass
class TrustScore:
    """Trust score result"""
    entity_id: str
    overall_score: float
    factor_scores: Dict[str, float]
    confidence: float
    timestamp: datetime
    rationale: str
    risk_level: str

class ContinuousTrustEngine:
    """
    Continuous Trust Scoring Engine for real-time trust evaluation
    """
    
    def __init__(self):
        self.trust_factors = TrustFactors()
        self.entity_profiles = {}
        self.behavioral_baselines = {}
        self.trust_history = {}
        self.geographic_risk_zones = {
            'high_risk': ['CN', 'RU', 'KP', 'IR'],
            'medium_risk': ['BR', 'IN', 'MX', 'TH'],
            'low_risk': ['US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU']
        }

        self._initialize_demo_data()
        
        logger.info("🔐 Continuous Trust Engine initialized")

    def _initialize_demo_data(self):
        """Initialize demo trust profiles"""
        demo_entities = [
            'user_001', 'user_002', 'user_003', 'admin_001', 'service_001'
        ]
        
        for entity in demo_entities:
            self.entity_profiles[entity] = {
                'baseline_behavior': {
                    'avg_request_rate': np.random.uniform(10, 100),
                    'typical_hours': list(range(9, 17)),
                    'common_endpoints': ['/api/data', '/api/status', '/api/health'],
                    'avg_session_duration': np.random.uniform(300, 3600)
                },
                'geographic_profile': {
                    'primary_country': 'US',
                    'risk_level': 'low_risk',
                    'timezone': 'America/New_York'
                },
                'device_profile': {
                    'device_type': 'desktop',
                    'browser': 'Chrome',
                    'os': 'Windows',
                    'trust_score': 0.8
                },
                'temporal_patterns': {
                    'peak_hours': [9, 10, 11, 14, 15, 16],
                    'off_hours': [0, 1, 2, 3, 4, 5, 6, 7, 22, 23],
                    'weekend_activity': 0.3
                }
            }

    async def calculate_trust_score(self, entity_id: str, context: Dict[str, Any]) -> TrustScore:
        """
        Calculate real-time trust score for an entity
        """
        try:

            if entity_id not in self.entity_profiles:
                await self._create_entity_profile(entity_id, context)
            
            profile = self.entity_profiles[entity_id]

            behavioral_score = await self._calculate_behavioral_score(entity_id, context, profile)
            geographic_score = await self._calculate_geographic_score(entity_id, context, profile)
            temporal_score = await self._calculate_temporal_score(entity_id, context, profile)
            device_score = await self._calculate_device_score(entity_id, context, profile)

            overall_score = (
                behavioral_score * self.trust_factors.behavioral +
                geographic_score * self.trust_factors.geographic +
                temporal_score * self.trust_factors.temporal +
                device_score * self.trust_factors.device
            )

            confidence = self._calculate_confidence(entity_id, context)

            risk_level = self._determine_risk_level(overall_score)

            rationale = self._generate_rationale(
                behavioral_score, geographic_score, temporal_score, device_score, overall_score
            )
            
            trust_score = TrustScore(
                entity_id=entity_id,
                overall_score=overall_score,
                factor_scores={
                    'behavioral': behavioral_score,
                    'geographic': geographic_score,
                    'temporal': temporal_score,
                    'device': device_score
                },
                confidence=confidence,
                timestamp=datetime.now(),
                rationale=rationale,
                risk_level=risk_level
            )

            await self._store_trust_score(trust_score)

            await self._update_behavioral_baseline(entity_id, context)
            
            return trust_score
            
        except Exception as e:
            logger.error(f"Error calculating trust score for {entity_id}: {e}")
            return self._create_default_trust_score(entity_id)

    async def _calculate_behavioral_score(self, entity_id: str, context: Dict, profile: Dict) -> float:
        """Calculate behavioral trust score"""
        baseline = profile['baseline_behavior']
        current_behavior = context.get('behavior', {})
        
        score = 1.0

        current_rate = current_behavior.get('request_rate', baseline['avg_request_rate'])
        rate_deviation = abs(current_rate - baseline['avg_request_rate']) / baseline['avg_request_rate']
        if rate_deviation > 2.0:
            score -= 0.3
        elif rate_deviation > 1.0:
            score -= 0.15

        current_endpoints = current_behavior.get('endpoints', [])
        if current_endpoints:
            endpoint_similarity = len(set(current_endpoints) & set(baseline['common_endpoints'])) / len(baseline['common_endpoints'])
            score *= (0.5 + endpoint_similarity * 0.5)

        current_duration = current_behavior.get('session_duration', baseline['avg_session_duration'])
        duration_deviation = abs(current_duration - baseline['avg_session_duration']) / baseline['avg_session_duration']
        if duration_deviation > 1.5:
            score -= 0.2
        
        return max(0.0, min(1.0, score))

    async def _calculate_geographic_score(self, entity_id: str, context: Dict, profile: Dict) -> float:
        """Calculate geographic trust score"""
        current_country = context.get('geographic', {}).get('country', 'US')
        baseline_country = profile['geographic_profile']['primary_country']

        if current_country == baseline_country:
            return 1.0

        for risk_level, countries in self.geographic_risk_zones.items():
            if current_country in countries:
                if risk_level == 'high_risk':
                    return 0.3
                elif risk_level == 'medium_risk':
                    return 0.6
                else:
                    return 0.8

        return 0.5

    async def _calculate_temporal_score(self, entity_id: str, context: Dict, profile: Dict) -> float:
        """Calculate temporal trust score"""
        current_hour = datetime.now().hour
        current_day = datetime.now().weekday()
        patterns = profile['temporal_patterns']
        
        score = 1.0

        if current_day >= 5:
            weekend_factor = patterns['weekend_activity']
            if np.random.random() > weekend_factor:
                score -= 0.2

        if current_hour in patterns['off_hours']:
            score -= 0.3

        if current_hour in patterns['peak_hours']:
            score += 0.1
        
        return max(0.0, min(1.0, score))

    async def _calculate_device_score(self, entity_id: str, context: Dict, profile: Dict) -> float:
        """Calculate device trust score"""
        current_device = context.get('device', {})
        baseline_device = profile['device_profile']
        
        score = baseline_device['trust_score']

        if current_device.get('device_type') != baseline_device['device_type']:
            score -= 0.2

        if current_device.get('browser') != baseline_device['browser']:
            score -= 0.1

        if current_device.get('os') != baseline_device['os']:
            score -= 0.1
        
        return max(0.0, min(1.0, score))

    def _calculate_confidence(self, entity_id: str, context: Dict) -> float:
        """Calculate confidence in trust score"""
        confidence = 0.5

        if entity_id in self.trust_history:
            history_length = len(self.trust_history[entity_id])
            confidence += min(0.4, history_length * 0.01)

        context_completeness = sum(1 for key in ['behavior', 'geographic', 'device'] if key in context) / 3
        confidence += context_completeness * 0.1
        
        return min(1.0, confidence)

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from trust score"""
        if score >= 0.8:
            return 'low'
        elif score >= 0.6:
            return 'medium'
        elif score >= 0.4:
            return 'high'
        else:
            return 'critical'

    def _generate_rationale(self, behavioral: float, geographic: float, temporal: float, device: float, overall: float) -> str:
        """Generate human-readable rationale for trust score"""
        factors = []
        
        if behavioral < 0.6:
            factors.append("unusual behavioral patterns")
        if geographic < 0.6:
            factors.append("suspicious geographic location")
        if temporal < 0.6:
            factors.append("atypical timing patterns")
        if device < 0.6:
            factors.append("device inconsistencies")
        
        if not factors:
            return f"Trust score {overall:.2f}: Normal activity patterns detected"
        else:
            return f"Trust score {overall:.2f}: Concerns raised by {', '.join(factors)}"

    async def _create_entity_profile(self, entity_id: str, context: Dict):
        """Create new entity profile"""
        self.entity_profiles[entity_id] = {
            'baseline_behavior': {
                'avg_request_rate': context.get('behavior', {}).get('request_rate', 50),
                'typical_hours': list(range(9, 17)),
                'common_endpoints': context.get('behavior', {}).get('endpoints', ['/api/data']),
                'avg_session_duration': context.get('behavior', {}).get('session_duration', 1800)
            },
            'geographic_profile': {
                'primary_country': context.get('geographic', {}).get('country', 'US'),
                'risk_level': 'low_risk',
                'timezone': context.get('geographic', {}).get('timezone', 'UTC')
            },
            'device_profile': {
                'device_type': context.get('device', {}).get('device_type', 'unknown'),
                'browser': context.get('device', {}).get('browser', 'unknown'),
                'os': context.get('device', {}).get('os', 'unknown'),
                'trust_score': 0.7
            },
            'temporal_patterns': {
                'peak_hours': [9, 10, 11, 14, 15, 16],
                'off_hours': [0, 1, 2, 3, 4, 5, 6, 7, 22, 23],
                'weekend_activity': 0.3
            }
        }

    async def _update_behavioral_baseline(self, entity_id: str, context: Dict):
        """Update behavioral baseline with new data"""
        if entity_id not in self.entity_profiles:
            return
        
        profile = self.entity_profiles[entity_id]
        behavior = context.get('behavior', {})

        alpha = 0.1
        if 'request_rate' in behavior:
            profile['baseline_behavior']['avg_request_rate'] = (
                (1 - alpha) * profile['baseline_behavior']['avg_request_rate'] +
                alpha * behavior['request_rate']
            )

    async def _store_trust_score(self, trust_score: TrustScore):
        """Store trust score in history"""
        if trust_score.entity_id not in self.trust_history:
            self.trust_history[trust_score.entity_id] = []
        
        self.trust_history[trust_score.entity_id].append(trust_score)

        if len(self.trust_history[trust_score.entity_id]) > 100:
            self.trust_history[trust_score.entity_id] = self.trust_history[trust_score.entity_id][-100:]

    def _create_default_trust_score(self, entity_id: str) -> TrustScore:
        """Create default trust score when calculation fails"""
        return TrustScore(
            entity_id=entity_id,
            overall_score=0.5,
            factor_scores={'behavioral': 0.5, 'geographic': 0.5, 'temporal': 0.5, 'device': 0.5},
            confidence=0.1,
            timestamp=datetime.now(),
            rationale="Default trust score due to insufficient data",
            risk_level='medium'
        )

    async def get_trust_statistics(self) -> Dict[str, Any]:
        """Get trust engine statistics"""
        total_entities = len(self.entity_profiles)
        total_scores = sum(len(scores) for scores in self.trust_history.values())

        risk_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for scores in self.trust_history.values():
            if scores:
                latest_score = scores[-1]
                risk_distribution[latest_score.risk_level] += 1
        
        return {
            'total_entities': total_entities,
            'total_trust_evaluations': total_scores,
            'risk_distribution': risk_distribution,
            'average_confidence': np.mean([
                score.confidence for scores in self.trust_history.values() 
                for score in scores[-10:]
            ]) if total_scores > 0 else 0.0,
            'trust_engine_status': 'active'
        }

    async def get_entity_trust_history(self, entity_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get trust history for a specific entity"""
        if entity_id not in self.trust_history:
            return []
        
        scores = self.trust_history[entity_id][-limit:]
        return [
            {
                'timestamp': score.timestamp.isoformat(),
                'overall_score': score.overall_score,
                'risk_level': score.risk_level,
                'confidence': score.confidence,
                'rationale': score.rationale,
                'factor_scores': score.factor_scores
            }
            for score in scores
        ]