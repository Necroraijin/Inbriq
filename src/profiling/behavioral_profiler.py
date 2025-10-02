"""
Advanced Behavioral Profiling System - Deep behavioral fingerprinting
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from dataclasses import dataclass
from collections import defaultdict, deque
import json
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class BehavioralPattern:
    """Represents a behavioral pattern"""
    pattern_id: str
    pattern_type: str
    frequency: float
    confidence: float
    last_seen: datetime
    metadata: Dict[str, Any]

@dataclass
class BehavioralFingerprint:
    """Complete behavioral fingerprint for an entity"""
    entity_id: str
    fingerprint_hash: str
    patterns: Dict[str, BehavioralPattern]
    baseline_metrics: Dict[str, float]
    anomaly_scores: Dict[str, float]
    last_updated: datetime
    confidence: float

class AdvancedBehavioralProfiler:
    """
    Advanced Behavioral Profiling System for deep behavioral fingerprinting
    """
    
    def __init__(self):
        self.entity_profiles = {}
        self.pattern_library = {}
        self.behavioral_models = {
            'api_patterns': APIPatternModel(),
            'timing_analysis': TimingAnalysisModel(),
            'resource_usage': ResourceUsageModel(),
            'sequence_analysis': SequenceAnalysisModel(),
            'network_behavior': NetworkBehaviorModel()
        }

        self.analysis_window = timedelta(hours=24)
        self.pattern_threshold = 0.7
        self.anomaly_threshold = 0.8

        self._initialize_demo_patterns()
        
        logger.info("🧠 Advanced Behavioral Profiler initialized")

    def _initialize_demo_patterns(self):
        """Initialize demo behavioral patterns"""
        self.pattern_library = {
            'normal_user': {
                'api_patterns': ['/api/data', '/api/status', '/api/health'],
                'timing_patterns': {'peak_hours': [9, 10, 11, 14, 15, 16]},
                'resource_patterns': {'cpu_usage': 0.3, 'memory_usage': 0.4},
                'sequence_patterns': ['login', 'data_access', 'logout']
            },
            'admin_user': {
                'api_patterns': ['/api/admin', '/api/users', '/api/system'],
                'timing_patterns': {'peak_hours': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]},
                'resource_patterns': {'cpu_usage': 0.5, 'memory_usage': 0.6},
                'sequence_patterns': ['admin_login', 'user_management', 'system_config']
            },
            'service_account': {
                'api_patterns': ['/api/service', '/api/health', '/api/metrics'],
                'timing_patterns': {'continuous': True},
                'resource_patterns': {'cpu_usage': 0.2, 'memory_usage': 0.3},
                'sequence_patterns': ['service_start', 'health_check', 'metrics_collection']
            }
        }

    async def build_behavioral_fingerprint(self, entity_id: str, behavior_data: Dict[str, Any]) -> BehavioralFingerprint:
        """
        Build comprehensive behavioral fingerprint for an entity
        """
        try:

            patterns = await self._extract_behavioral_patterns(entity_id, behavior_data)

            baseline_metrics = await self._calculate_baseline_metrics(entity_id, behavior_data)

            anomaly_scores = await self._calculate_anomaly_scores(entity_id, behavior_data, baseline_metrics)

            fingerprint_hash = self._generate_fingerprint_hash(patterns, baseline_metrics)

            confidence = self._calculate_fingerprint_confidence(patterns, baseline_metrics)
            
            fingerprint = BehavioralFingerprint(
                entity_id=entity_id,
                fingerprint_hash=fingerprint_hash,
                patterns=patterns,
                baseline_metrics=baseline_metrics,
                anomaly_scores=anomaly_scores,
                last_updated=datetime.now(),
                confidence=confidence
            )

            self.entity_profiles[entity_id] = fingerprint
            
            return fingerprint
            
        except Exception as e:
            logger.error(f"Error building behavioral fingerprint for {entity_id}: {e}")
            return self._create_default_fingerprint(entity_id)

    async def _extract_behavioral_patterns(self, entity_id: str, behavior_data: Dict[str, Any]) -> Dict[str, BehavioralPattern]:
        """Extract behavioral patterns from data"""
        patterns = {}

        api_patterns = await self.behavioral_models['api_patterns'].analyze(behavior_data.get('api_calls', []))
        patterns['api_patterns'] = BehavioralPattern(
            pattern_id=f"{entity_id}_api",
            pattern_type='api_usage',
            frequency=api_patterns['frequency'],
            confidence=api_patterns['confidence'],
            last_seen=datetime.now(),
            metadata=api_patterns
        )

        timing_patterns = await self.behavioral_models['timing_analysis'].analyze(behavior_data.get('timing_data', []))
        patterns['timing_patterns'] = BehavioralPattern(
            pattern_id=f"{entity_id}_timing",
            pattern_type='temporal_behavior',
            frequency=timing_patterns['frequency'],
            confidence=timing_patterns['confidence'],
            last_seen=datetime.now(),
            metadata=timing_patterns
        )

        resource_patterns = await self.behavioral_models['resource_usage'].analyze(behavior_data.get('resource_usage', {}))
        patterns['resource_patterns'] = BehavioralPattern(
            pattern_id=f"{entity_id}_resource",
            pattern_type='resource_consumption',
            frequency=resource_patterns['frequency'],
            confidence=resource_patterns['confidence'],
            last_seen=datetime.now(),
            metadata=resource_patterns
        )

        sequence_patterns = await self.behavioral_models['sequence_analysis'].analyze(behavior_data.get('action_sequence', []))
        patterns['sequence_patterns'] = BehavioralPattern(
            pattern_id=f"{entity_id}_sequence",
            pattern_type='action_sequence',
            frequency=sequence_patterns['frequency'],
            confidence=sequence_patterns['confidence'],
            last_seen=datetime.now(),
            metadata=sequence_patterns
        )

        network_patterns = await self.behavioral_models['network_behavior'].analyze(behavior_data.get('network_data', {}))
        patterns['network_patterns'] = BehavioralPattern(
            pattern_id=f"{entity_id}_network",
            pattern_type='network_behavior',
            frequency=network_patterns['frequency'],
            confidence=network_patterns['confidence'],
            last_seen=datetime.now(),
            metadata=network_patterns
        )
        
        return patterns

    async def _calculate_baseline_metrics(self, entity_id: str, behavior_data: Dict[str, Any]) -> Dict[str, float]:
        """Calculate baseline behavioral metrics"""
        metrics = {}

        request_rate = behavior_data.get('request_rate', 0)
        metrics['avg_request_rate'] = request_rate

        session_duration = behavior_data.get('session_duration', 0)
        metrics['avg_session_duration'] = session_duration

        api_calls = behavior_data.get('api_calls', [])
        unique_endpoints = len(set(api_calls))
        metrics['endpoint_diversity'] = unique_endpoints

        timing_data = behavior_data.get('timing_data', [])
        if timing_data:
            metrics['peak_hour_activity'] = max(timing_data) if timing_data else 0
            metrics['off_hour_activity'] = min(timing_data) if timing_data else 0

        resource_usage = behavior_data.get('resource_usage', {})
        metrics['avg_cpu_usage'] = resource_usage.get('cpu', 0.3)
        metrics['avg_memory_usage'] = resource_usage.get('memory', 0.4)
        metrics['avg_network_usage'] = resource_usage.get('network', 0.2)
        
        return metrics

    async def _calculate_anomaly_scores(self, entity_id: str, behavior_data: Dict[str, Any], baseline_metrics: Dict[str, float]) -> Dict[str, float]:
        """Calculate anomaly scores for different behavioral aspects"""
        anomaly_scores = {}

        current_rate = behavior_data.get('request_rate', 0)
        baseline_rate = baseline_metrics.get('avg_request_rate', 0)
        if baseline_rate > 0:
            rate_deviation = abs(current_rate - baseline_rate) / baseline_rate
            anomaly_scores['request_rate_anomaly'] = min(1.0, rate_deviation)
        else:
            anomaly_scores['request_rate_anomaly'] = 0.0

        api_calls = behavior_data.get('api_calls', [])
        if api_calls:

            pattern_similarity = self._calculate_pattern_similarity(api_calls)
            anomaly_scores['api_pattern_anomaly'] = 1.0 - pattern_similarity
        else:
            anomaly_scores['api_pattern_anomaly'] = 0.0

        current_hour = datetime.now().hour
        timing_data = behavior_data.get('timing_data', [])
        if timing_data:
            hour_activity = timing_data[current_hour] if current_hour < len(timing_data) else 0
            avg_activity = np.mean(timing_data)
            if avg_activity > 0:
                timing_deviation = abs(hour_activity - avg_activity) / avg_activity
                anomaly_scores['timing_anomaly'] = min(1.0, timing_deviation)
            else:
                anomaly_scores['timing_anomaly'] = 0.0
        else:
            anomaly_scores['timing_anomaly'] = 0.0

        resource_usage = behavior_data.get('resource_usage', {})
        for resource in ['cpu', 'memory', 'network']:
            current_usage = resource_usage.get(resource, 0)
            baseline_usage = baseline_metrics.get(f'avg_{resource}_usage', 0)
            if baseline_usage > 0:
                usage_deviation = abs(current_usage - baseline_usage) / baseline_usage
                anomaly_scores[f'{resource}_usage_anomaly'] = min(1.0, usage_deviation)
            else:
                anomaly_scores[f'{resource}_usage_anomaly'] = 0.0

        anomaly_scores['overall_anomaly'] = np.mean(list(anomaly_scores.values()))
        
        return anomaly_scores

    def _calculate_pattern_similarity(self, api_calls: List[str]) -> float:
        """Calculate similarity to known behavioral patterns"""
        if not api_calls:
            return 0.0
        
        max_similarity = 0.0
        for pattern_name, pattern_data in self.pattern_library.items():
            pattern_apis = pattern_data.get('api_patterns', [])
            if pattern_apis:
                intersection = len(set(api_calls) & set(pattern_apis))
                union = len(set(api_calls) | set(pattern_apis))
                similarity = intersection / union if union > 0 else 0.0
                max_similarity = max(max_similarity, similarity)
        
        return max_similarity

    def _generate_fingerprint_hash(self, patterns: Dict[str, BehavioralPattern], baseline_metrics: Dict[str, float]) -> str:
        """Generate unique hash for behavioral fingerprint"""
        fingerprint_data = {
            'patterns': {k: v.pattern_type for k, v in patterns.items()},
            'metrics': baseline_metrics
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def _calculate_fingerprint_confidence(self, patterns: Dict[str, BehavioralPattern], baseline_metrics: Dict[str, float]) -> float:
        """Calculate confidence in behavioral fingerprint"""
        if not patterns:
            return 0.0

        pattern_confidences = [pattern.confidence for pattern in patterns.values()]
        avg_confidence = np.mean(pattern_confidences)

        data_completeness = len(baseline_metrics) / 10.0
        completeness_factor = min(1.0, data_completeness)
        
        return avg_confidence * completeness_factor

    def _create_default_fingerprint(self, entity_id: str) -> BehavioralFingerprint:
        """Create default fingerprint when analysis fails"""
        return BehavioralFingerprint(
            entity_id=entity_id,
            fingerprint_hash="default",
            patterns={},
            baseline_metrics={},
            anomaly_scores={'overall_anomaly': 0.5},
            last_updated=datetime.now(),
            confidence=0.1
        )

    async def detect_behavioral_anomalies(self, entity_id: str, current_behavior: Dict[str, Any]) -> Dict[str, Any]:
        """Detect behavioral anomalies for an entity"""
        if entity_id not in self.entity_profiles:
            return {'anomaly_detected': False, 'confidence': 0.0}
        
        fingerprint = self.entity_profiles[entity_id]

        current_anomaly_scores = await self._calculate_anomaly_scores(entity_id, current_behavior, fingerprint.baseline_metrics)

        anomaly_detected = current_anomaly_scores['overall_anomaly'] > self.anomaly_threshold

        confidence = fingerprint.confidence if anomaly_detected else 1.0 - fingerprint.confidence
        
        return {
            'anomaly_detected': anomaly_detected,
            'confidence': confidence,
            'anomaly_scores': current_anomaly_scores,
            'baseline_metrics': fingerprint.baseline_metrics,
            'pattern_deviations': self._identify_pattern_deviations(fingerprint.patterns, current_behavior)
        }

    def _identify_pattern_deviations(self, patterns: Dict[str, BehavioralPattern], current_behavior: Dict[str, Any]) -> List[str]:
        """Identify specific pattern deviations"""
        deviations = []

        if 'api_patterns' in patterns:
            current_apis = current_behavior.get('api_calls', [])
            if current_apis:
                pattern_similarity = self._calculate_pattern_similarity(current_apis)
                if pattern_similarity < 0.5:
                    deviations.append("unusual API access patterns")

        if 'timing_patterns' in patterns:
            current_hour = datetime.now().hour
            timing_data = current_behavior.get('timing_data', [])
            if timing_data and current_hour < len(timing_data):
                hour_activity = timing_data[current_hour]
                avg_activity = np.mean(timing_data)
                if hour_activity > avg_activity * 2:
                    deviations.append("unusual timing patterns")

        resource_usage = current_behavior.get('resource_usage', {})
        for resource in ['cpu', 'memory', 'network']:
            if resource in resource_usage:
                usage = resource_usage[resource]
                if usage > 0.8:
                    deviations.append(f"high {resource} usage")
        
        return deviations

    async def get_behavioral_statistics(self) -> Dict[str, Any]:
        """Get behavioral profiling statistics"""
        total_entities = len(self.entity_profiles)
        total_patterns = sum(len(fp.patterns) for fp in self.entity_profiles.values())

        avg_confidence = np.mean([fp.confidence for fp in self.entity_profiles.values()]) if total_entities > 0 else 0.0

        anomaly_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for fp in self.entity_profiles.values():
            overall_anomaly = fp.anomaly_scores.get('overall_anomaly', 0.0)
            if overall_anomaly < 0.3:
                anomaly_distribution['low'] += 1
            elif overall_anomaly < 0.6:
                anomaly_distribution['medium'] += 1
            elif overall_anomaly < 0.8:
                anomaly_distribution['high'] += 1
            else:
                anomaly_distribution['critical'] += 1
        
        return {
            'total_entities_profiled': total_entities,
            'total_patterns_identified': total_patterns,
            'average_confidence': avg_confidence,
            'anomaly_distribution': anomaly_distribution,
            'profiler_status': 'active'
        }

class APIPatternModel:
    """API pattern analysis model"""
    
    async def analyze(self, api_calls: List[str]) -> Dict[str, Any]:
        if not api_calls:
            return {'frequency': 0.0, 'confidence': 0.0, 'patterns': []}

        unique_apis = len(set(api_calls))
        total_calls = len(api_calls)
        frequency = total_calls / 100.0

        confidence = min(1.0, unique_apis / 10.0)
        
        return {
            'frequency': frequency,
            'confidence': confidence,
            'patterns': list(set(api_calls)),
            'unique_endpoints': unique_apis,
            'total_calls': total_calls
        }

class TimingAnalysisModel:
    """Temporal behavior analysis model"""
    
    async def analyze(self, timing_data: List[float]) -> Dict[str, Any]:
        if not timing_data:
            return {'frequency': 0.0, 'confidence': 0.0, 'patterns': {}}

        avg_activity = np.mean(timing_data)
        peak_hours = [i for i, val in enumerate(timing_data) if val > avg_activity * 1.5]
        
        frequency = avg_activity / 100.0
        confidence = min(1.0, len(peak_hours) / 24.0)
        
        return {
            'frequency': frequency,
            'confidence': confidence,
            'patterns': {
                'peak_hours': peak_hours,
                'avg_activity': avg_activity,
                'activity_variance': np.var(timing_data)
            }
        }

class ResourceUsageModel:
    """Resource usage analysis model"""
    
    async def analyze(self, resource_data: Dict[str, float]) -> Dict[str, Any]:
        if not resource_data:
            return {'frequency': 0.0, 'confidence': 0.0, 'patterns': {}}

        avg_usage = np.mean(list(resource_data.values()))
        frequency = avg_usage

        confidence = min(1.0, len(resource_data) / 3.0)
        
        return {
            'frequency': frequency,
            'confidence': confidence,
            'patterns': resource_data,
            'avg_usage': avg_usage,
            'usage_variance': np.var(list(resource_data.values()))
        }

class SequenceAnalysisModel:
    """Action sequence analysis model"""
    
    async def analyze(self, action_sequence: List[str]) -> Dict[str, Any]:
        if not action_sequence:
            return {'frequency': 0.0, 'confidence': 0.0, 'patterns': []}

        unique_actions = len(set(action_sequence))
        sequence_length = len(action_sequence)
        frequency = sequence_length / 100.0

        confidence = min(1.0, unique_actions / 10.0)
        
        return {
            'frequency': frequency,
            'confidence': confidence,
            'patterns': action_sequence,
            'unique_actions': unique_actions,
            'sequence_length': sequence_length
        }

class NetworkBehaviorModel:
    """Network behavior analysis model"""
    
    async def analyze(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        if not network_data:
            return {'frequency': 0.0, 'confidence': 0.0, 'patterns': {}}

        bandwidth = network_data.get('bandwidth', 0)
        packet_rate = network_data.get('packet_rate', 0)
        connection_count = network_data.get('connections', 0)
        
        frequency = (bandwidth + packet_rate + connection_count) / 300.0
        confidence = min(1.0, len(network_data) / 5.0)
        
        return {
            'frequency': frequency,
            'confidence': confidence,
            'patterns': network_data,
            'network_activity': bandwidth + packet_rate + connection_count
        }