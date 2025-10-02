"""
Enhanced API Routes - New features and capabilities
"""

from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
import logging
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter()

trust_engine = None
behavioral_profiler = None
explainability_engine = None
performance_engine = None

@router.get("/trust/scores")
async def get_trust_scores():
    """Get current trust scores for all entities"""
    try:
        if not trust_engine:
            raise HTTPException(status_code=503, detail="Trust engine not initialized")
        
        statistics = await trust_engine.get_trust_statistics()
        return {
            "trust_statistics": statistics,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting trust scores: {e}")
        raise HTTPException(status_code=500, detail="Failed to get trust scores")

@router.post("/trust/evaluate")
async def evaluate_trust(entity_id: str, context: dict):
    """Evaluate trust score for a specific entity"""
    try:
        if not trust_engine:
            raise HTTPException(status_code=503, detail="Trust engine not initialized")
        
        trust_score = await trust_engine.calculate_trust_score(entity_id, context)
        return {
            "entity_id": trust_score.entity_id,
            "overall_score": trust_score.overall_score,
            "factor_scores": trust_score.factor_scores,
            "confidence": trust_score.confidence,
            "risk_level": trust_score.risk_level,
            "rationale": trust_score.rationale,
            "timestamp": trust_score.timestamp.isoformat()
        }
    except Exception as e:
        logger.error(f"Error evaluating trust: {e}")
        raise HTTPException(status_code=500, detail="Failed to evaluate trust")

@router.get("/behavioral/profiles")
async def get_behavioral_profiles():
    """Get behavioral profiling statistics"""
    try:
        if not behavioral_profiler:
            raise HTTPException(status_code=503, detail="Behavioral profiler not initialized")
        
        statistics = await behavioral_profiler.get_behavioral_statistics()
        return {
            "behavioral_statistics": statistics,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting behavioral profiles: {e}")
        raise HTTPException(status_code=500, detail="Failed to get behavioral profiles")

@router.post("/behavioral/analyze")
async def analyze_behavior(entity_id: str, behavior_data: dict):
    """Analyze behavioral patterns for an entity"""
    try:
        if not behavioral_profiler:
            raise HTTPException(status_code=503, detail="Behavioral profiler not initialized")
        
        fingerprint = await behavioral_profiler.build_behavioral_fingerprint(entity_id, behavior_data)
        return {
            "entity_id": fingerprint.entity_id,
            "fingerprint_hash": fingerprint.fingerprint_hash,
            "confidence": fingerprint.confidence,
            "anomaly_scores": fingerprint.anomaly_scores,
            "baseline_metrics": fingerprint.baseline_metrics,
            "last_updated": fingerprint.last_updated.isoformat()
        }
    except Exception as e:
        logger.error(f"Error analyzing behavior: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze behavior")

@router.get("/performance/metrics")
async def get_performance_metrics():
    """Get performance metrics and benchmarks"""
    try:
        if not performance_engine:
            raise HTTPException(status_code=503, detail="Performance engine not initialized")
        
        statistics = await performance_engine.get_performance_statistics()
        benchmarks = await performance_engine.get_benchmark_results()
        recommendations = await performance_engine.get_optimization_recommendations()
        
        return {
            "performance_statistics": statistics,
            "benchmarks": benchmarks,
            "optimization_recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")

@router.post("/performance/optimize/{recommendation_id}")
async def apply_optimization(recommendation_id: str):
    """Apply performance optimization recommendation"""
    try:
        if not performance_engine:
            raise HTTPException(status_code=503, detail="Performance engine not initialized")
        
        result = await performance_engine.apply_optimization(recommendation_id)
        return result
    except Exception as e:
        logger.error(f"Error applying optimization: {e}")
        raise HTTPException(status_code=500, detail="Failed to apply optimization")

@router.get("/explainability/decisions")
async def get_decision_history(limit: int = 20):
    """Get decision history with explanations"""
    try:
        if not explainability_engine:
            raise HTTPException(status_code=503, detail="Explainability engine not initialized")
        
        decisions = await explainability_engine.search_decisions(limit=limit)
        statistics = await explainability_engine.get_explainability_statistics()
        
        return {
            "decisions": [
                {
                    "decision_id": d.decision_id,
                    "decision_type": d.decision_type.value,
                    "entity_id": d.entity_id,
                    "decision_outcome": d.decision_outcome,
                    "confidence_level": d.confidence_level.value,
                    "timestamp": d.timestamp.isoformat(),
                    "rationale": d.rationale
                }
                for d in decisions
            ],
            "statistics": statistics,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting decision history: {e}")
        raise HTTPException(status_code=500, detail="Failed to get decision history")

@router.get("/benchmarks/research")
async def get_research_benchmarks():
    """Get comparison with research benchmarks"""
    try:
        if not performance_engine:
            raise HTTPException(status_code=503, detail="Performance engine not initialized")
        
        statistics = await performance_engine.get_performance_statistics()
        research_compliance = statistics.get('research_compliance', {})
        
        return {
            "research_benchmarks": {
                "decision_latency": {"target": 220, "unit": "ms"},
                "f1_score": {"target": 0.89, "unit": "score"},
                "precision": {"target": 0.91, "unit": "score"},
                "recall": {"target": 0.87, "unit": "score"},
                "cpu_overhead": {"target": 0.1, "unit": "percentage"},
                "memory_overhead": {"target": 0.1, "unit": "percentage"}
            },
            "current_performance": research_compliance,
            "compliance_summary": {
                "total_benchmarks": len(research_compliance),
                "compliant_benchmarks": len([b for b in research_compliance.values() if b.get('compliant', False)]),
                "overall_compliance": len([b for b in research_compliance.values() if b.get('compliant', False)]) / len(research_compliance) if research_compliance else 0
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting research benchmarks: {e}")
        raise HTTPException(status_code=500, detail="Failed to get research benchmarks")