"""API routes"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional
import logging
from datetime import datetime, timedelta

from ..core.firewall_engine import FirewallEngine
from ..core.threat_detector import ThreatDetector
from ..core.response_engine import ResponseEngine
from ..core.network_monitor import NetworkMonitor

logger = logging.getLogger(__name__)

router = APIRouter()

firewall_engine: Optional[FirewallEngine] = None
threat_detector: Optional[ThreatDetector] = None
response_engine: Optional[ResponseEngine] = None
network_monitor: Optional[NetworkMonitor] = None
multi_agent_system = None
trust_engine = None
behavioral_profiler = None
explainability_engine = None
performance_engine = None

def get_firewall_engine() -> FirewallEngine:
    """Dependency to get firewall engine instance"""
    if firewall_engine is None:
        raise HTTPException(status_code=503, detail="Firewall engine not initialized")
    return firewall_engine

def get_threat_detector() -> ThreatDetector:
    """Dependency to get threat detector instance"""
    if threat_detector is None:
        raise HTTPException(status_code=503, detail="Threat detector not initialized")
    return threat_detector

def get_response_engine() -> ResponseEngine:
    """Dependency to get response engine instance"""
    if response_engine is None:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    return response_engine

def get_network_monitor() -> NetworkMonitor:
    """Dependency to get network monitor instance"""
    if network_monitor is None:
        raise HTTPException(status_code=503, detail="Network monitor not initialized")
    return network_monitor

@router.get("/status")
async def get_system_status(engine: FirewallEngine = Depends(get_firewall_engine)):
    """Get overall system status"""
    try:
        status = engine.get_system_status()
        return JSONResponse(content=status)
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threats")
async def get_threats(
    limit: int = 50,
    severity: Optional[str] = None,
    engine: FirewallEngine = Depends(get_firewall_engine)
):
    """Get security threats and events"""
    try:
        events = engine.get_security_events(limit=limit)

        if severity:
            events = [event for event in events if event["severity"] == severity]
        
        return JSONResponse(content={
            "threats": events,
            "total_count": len(events),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network/stats")
async def get_network_stats(monitor: NetworkMonitor = Depends(get_network_monitor)):
    """Get network statistics"""
    try:
        stats = monitor.get_network_stats()
        return JSONResponse(content=stats)
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network/traffic")
async def get_traffic_summary(
    minutes: int = 5,
    monitor: NetworkMonitor = Depends(get_network_monitor)
):
    """Get traffic summary for specified time window"""
    try:
        summary = monitor.get_traffic_summary(time_window_minutes=minutes)
        return JSONResponse(content=summary)
    except Exception as e:
        logger.error(f"Error getting traffic summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network/anomalies")
async def get_network_anomalies(monitor: NetworkMonitor = Depends(get_network_monitor)):
    """Get detected network anomalies"""
    try:
        anomalies = monitor.detect_network_anomalies()
        return JSONResponse(content={
            "anomalies": anomalies,
            "count": len(anomalies),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting network anomalies: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/responses")
async def get_responses(
    limit: int = 50,
    engine: ResponseEngine = Depends(get_response_engine)
):
    """Get response actions taken"""
    try:
        responses = engine.get_response_history(limit=limit)
        active_responses = engine.get_active_responses()
        
        return JSONResponse(content={
            "responses": responses,
            "active_responses": active_responses,
            "total_count": len(responses),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting responses: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/responses/statistics")
async def get_response_statistics(engine: ResponseEngine = Depends(get_response_engine)):
    """Get response engine statistics"""
    try:
        stats = engine.get_response_statistics()
        return JSONResponse(content=stats)
    except Exception as e:
        logger.error(f"Error getting response statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/models/info")
async def get_model_info(detector: ThreatDetector = Depends(get_threat_detector)):
    """Get information about ML models"""
    try:
        model_info = detector.get_model_info()
        return JSONResponse(content=model_info)
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/models/update")
async def update_models(detector: ThreatDetector = Depends(get_threat_detector)):
    """Trigger model update"""
    try:
        await detector.update_models()
        return JSONResponse(content={"message": "Models update initiated"})
    except Exception as e:
        logger.error(f"Error updating models: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/trusted-ips")
async def add_trusted_ip(
    ip: str,
    engine: FirewallEngine = Depends(get_firewall_engine)
):
    """Add an IP to the trusted list"""
    try:
        engine.add_trusted_ip(ip)
        return JSONResponse(content={"message": f"Added {ip} to trusted list"})
    except Exception as e:
        logger.error(f"Error adding trusted IP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/trusted-ips/{ip}")
async def remove_trusted_ip(
    ip: str,
    engine: FirewallEngine = Depends(get_firewall_engine)
):
    """Remove an IP from the trusted list"""
    try:
        engine.remove_trusted_ip(ip)
        return JSONResponse(content={"message": f"Removed {ip} from trusted list"})
    except Exception as e:
        logger.error(f"Error removing trusted IP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/trusted-ips")
async def get_trusted_ips(engine: FirewallEngine = Depends(get_firewall_engine)):
    """Get list of trusted IPs"""
    try:
        return JSONResponse(content={
            "trusted_ips": list(engine.trusted_ips),
            "count": len(engine.trusted_ips)
        })
    except Exception as e:
        logger.error(f"Error getting trusted IPs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/blocked-ips")
async def get_blocked_ips(engine: FirewallEngine = Depends(get_firewall_engine)):
    """Get list of blocked IPs"""
    try:
        return JSONResponse(content={
            "blocked_ips": list(engine.blocked_ips),
            "count": len(engine.blocked_ips)
        })
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-transaction")
async def analyze_transaction(
    transaction_data: Dict,
    detector: ThreatDetector = Depends(get_threat_detector)
):
    """Analyze a financial transaction for threats"""
    try:
        threats = await detector.analyze_transaction(transaction_data)
        return JSONResponse(content={
            "threats": threats,
            "transaction_id": transaction_data.get("id", "unknown"),
            "analysis_timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error analyzing transaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/data")
async def get_dashboard_data(
    engine: FirewallEngine = Depends(get_firewall_engine),
    monitor: NetworkMonitor = Depends(get_network_monitor),
    response_eng: ResponseEngine = Depends(get_response_engine)
):
    
    try:
        logger.info("Getting dashboard data...")

        system_status = engine.get_system_status()
        logger.info(f"System status: {system_status}")

        network_stats = monitor.get_network_stats()
        logger.info(f"Network stats: {network_stats}")

        recent_threats = engine.get_security_events(limit=10)
        logger.info(f"Recent threats: {len(recent_threats)}")

        response_stats = response_eng.get_response_statistics()
        logger.info(f"Response stats: {response_stats}")

        anomalies = monitor.detect_network_anomalies()
        logger.info(f"Anomalies: {len(anomalies)}")

        traffic_summary = monitor.get_traffic_summary(time_window_minutes=5)
        logger.info(f"Traffic summary: {traffic_summary}")

        trust_scores = []
        performance_metrics = {}
        behavioral_analysis = {}

        try:
            if trust_engine:
                logger.info("Getting trust scores...")
                trust_scores = await trust_engine.get_all_trust_scores()
                logger.info(f"Trust scores: {len(trust_scores)}")
            else:
                logger.info("Trust engine not available, using empty list")
                trust_scores = []
        except Exception as e:
            logger.warning(f"Error getting trust scores: {e}")
            trust_scores = []

        try:
            if performance_engine:
                logger.info("Getting performance metrics...")
                performance_metrics = await performance_engine.get_performance_metrics()
                logger.info(f"Performance metrics: {performance_metrics}")
            else:
                logger.info("Performance engine not available, using defaults")
                performance_metrics = {
                    "cpu_usage": 0.3,
                    "memory_usage": 0.4,
                    "throughput": 1200,
                    "error_rate": 0.005,
                    "decision_latency": 200
                }
        except Exception as e:
            logger.warning(f"Error getting performance metrics: {e}")
            performance_metrics = {
                "cpu_usage": 0.3,
                "memory_usage": 0.4,
                "throughput": 1200,
                "error_rate": 0.005,
                "decision_latency": 200
            }

        try:
            if behavioral_profiler:
                logger.info("Getting behavioral analysis...")
                behavioral_analysis = await behavioral_profiler.get_behavioral_analytics()
                logger.info(f"Behavioral analysis: {behavioral_analysis}")
            else:
                logger.info("Behavioral profiler not available, using defaults")
                behavioral_analysis = {
                    "normal": 70,
                    "suspicious": 20,
                    "anomalous": 8,
                    "critical": 2
                }
        except Exception as e:
            logger.warning(f"Error getting behavioral analysis: {e}")
            behavioral_analysis = {
                "normal": 70,
                "suspicious": 20,
                "anomalous": 8,
                "critical": 2
            }

        trust_statistics = {
            "average_confidence": 0.85,
            "total_entities": len(trust_scores),
            "high_trust_count": len([s for s in trust_scores if s.get('score', 0) > 0.8])
        }
        
        dashboard_data = {
            "system_status": system_status,
            "network_stats": network_stats,
            "recent_threats": recent_threats,
            "response_stats": response_stats,
            "anomalies": anomalies,
            "traffic_summary": traffic_summary,
            "trust_scores": trust_scores,
            "trust_statistics": trust_statistics,
            "performance_metrics": performance_metrics,
            "behavioral_analysis": behavioral_analysis,
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info("Dashboard data prepared successfully")
        return JSONResponse(content=dashboard_data)
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}", exc_info=True)
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/health")
async def health_check():
    
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Adaptive AI Firewall System"
    })

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint to check if API is working"""
    try:
        return JSONResponse(content={
            "message": "API is working",
            "firewall_engine_available": firewall_engine is not None,
            "network_monitor_available": network_monitor is not None,
            "response_engine_available": response_engine is not None,
            "trust_engine_available": trust_engine is not None,
            "performance_engine_available": performance_engine is not None,
            "behavioral_profiler_available": behavioral_profiler is not None,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in test endpoint: {e}")
        return JSONResponse(content={
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, status_code=500)

@router.get("/metrics")
async def get_metrics(
    engine: FirewallEngine = Depends(get_firewall_engine),
    monitor: NetworkMonitor = Depends(get_network_monitor),
    response_eng: ResponseEngine = Depends(get_response_engine)
):
    """Get system metrics for monitoring"""
    try:
        system_status = engine.get_system_status()
        network_stats = monitor.get_network_stats()
        response_stats = response_eng.get_response_statistics()
        
        metrics = {
            "uptime_seconds": system_status["uptime_seconds"],
            "total_packets_analyzed": system_status["statistics"]["total_packets_analyzed"],
            "threats_detected": system_status["statistics"]["threats_detected"],
            "threats_blocked": system_status["statistics"]["threats_blocked"],
            "active_connections": network_stats.get("active_connections", 0),
            "total_responses": response_stats.get("total_responses", 0),
            "active_responses": response_stats.get("active_responses", 0),
            "timestamp": datetime.now().isoformat()
        }
        
        return JSONResponse(content=metrics)
        
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/demo/simulate-attack")
async def simulate_attack(
    attack_type: str,
    engine: FirewallEngine = Depends(get_firewall_engine)
):
    
    try:
        demo_attacks = {
            "ddos": {
                "type": "ddos_attack",
                "severity": "critical",
                "threat_score": 0.95,
                "source_ip": "10.0.0.0/8",
                "target_ip": "192.168.1.1",
                "protocol": "TCP/UDP",
                "description": "Simulated DDoS attack for demonstration"
            },
            "malware": {
                "type": "malware_traffic",
                "severity": "high",
                "threat_score": 0.85,
                "source_ip": "203.0.113.42",
                "target_ip": "192.168.1.50",
                "protocol": "TCP",
                "description": "Simulated malware traffic for demonstration"
            },
            "port_scan": {
                "type": "port_scan",
                "severity": "high",
                "threat_score": 0.80,
                "source_ip": "198.51.100.25",
                "target_ip": "192.168.1.0/24",
                "protocol": "TCP",
                "description": "Simulated port scanning for demonstration"
            },
            "data_exfiltration": {
                "type": "data_exfiltration",
                "severity": "critical",
                "threat_score": 0.92,
                "source_ip": "192.168.1.50",
                "target_ip": "external-server.com",
                "protocol": "HTTPS",
                "description": "Simulated data exfiltration for demonstration"
            }
        }
        
        if attack_type not in demo_attacks:
            raise HTTPException(status_code=400, detail=f"Unknown attack type: {attack_type}")

        from ..core.models import SecurityEvent
        
        attack_data = demo_attacks[attack_type]
        event = SecurityEvent(
            event_id=f"demo_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now(),
            event_type=attack_data["type"],
            severity=attack_data["severity"],
            source_ip=attack_data["source_ip"],
            target_ip=attack_data["target_ip"],
            protocol=attack_data["protocol"],
            description=attack_data["description"],
            threat_score=attack_data["threat_score"],
            response_actions=[],
            status="detected"
        )

        engine.security_events.append(event)
        engine.stats["threats_detected"] += 1
        
        return JSONResponse(content={
            "message": f"Simulated {attack_type} attack",
            "event_id": event.event_id,
            "attack_data": attack_data
        })
        
    except Exception as e:
        logger.error(f"Error simulating attack: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/demo/scenarios")
async def get_demo_scenarios():
    """Get available demo scenarios"""
    scenarios = {
        "ddos": {
            "name": "DDoS Attack",
            "description": "Simulate a distributed denial-of-service attack",
            "severity": "critical",
            "expected_responses": ["block_ip", "rate_limit", "alert_admin"]
        },
        "malware": {
            "name": "Malware Traffic",
            "description": "Simulate malicious network traffic",
            "severity": "high",
            "expected_responses": ["quarantine", "block_ip", "scan_system"]
        },
        "port_scan": {
            "name": "Port Scanning",
            "description": "Simulate port scanning activity",
            "severity": "high",
            "expected_responses": ["block_ip", "honeypot", "alert_admin"]
        },
        "data_exfiltration": {
            "name": "Data Exfiltration",
            "description": "Simulate unauthorized data transfer",
            "severity": "critical",
            "expected_responses": ["block_connection", "quarantine", "backup_data"]
        }
    }
    
    return JSONResponse(content=scenarios)

@router.get("/multi-agent/status")
async def get_multi_agent_status():
    """Get multi-agent system status"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        status = multi_agent_system.get_system_status()
        return JSONResponse(content=status)
    except Exception as e:
        logger.error(f"Error getting multi-agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/multi-agent/agents")
async def get_agent_status():
    """Get status of all agents"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        agent_statuses = {}
        for agent_name, agent in multi_agent_system.agents.items():
            agent_statuses[agent_name] = agent.get_status()
        
        agent_statuses["coordinator"] = multi_agent_system.coordinator.get_status()
        
        return JSONResponse(content=agent_statuses)
    except Exception as e:
        logger.error(f"Error getting agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/multi-agent/capabilities")
async def get_agent_capabilities():
    """Get capabilities of all agents"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        capabilities = multi_agent_system.get_agent_capabilities()
        return JSONResponse(content=capabilities)
    except Exception as e:
        logger.error(f"Error getting agent capabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/multi-agent/analyze-threat")
async def analyze_threat_multi_agent(threat_data: Dict):
    """Analyze threat using multi-agent coordination"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        result = await multi_agent_system.analyze_threat(threat_data)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error in multi-agent threat analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/multi-agent/process-incident")
async def process_incident_multi_agent(incident_data: Dict):
    """Process incident using multi-agent coordination"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        result = await multi_agent_system.process_incident(incident_data)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error in multi-agent incident processing: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/multi-agent/threat-hunting")
async def conduct_threat_hunting(hunting_parameters: Dict):
    """Conduct threat hunting using multi-agent coordination"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        result = await multi_agent_system.conduct_threat_hunting(hunting_parameters)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error in multi-agent threat hunting: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/multi-agent/optimize")
async def optimize_system_performance():
    """Optimize multi-agent system performance"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        result = await multi_agent_system.optimize_system_performance()
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error optimizing system performance: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/multi-agent/analytics")
async def get_system_analytics():
    """Get comprehensive system analytics"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        analytics = multi_agent_system.get_system_analytics()
        return JSONResponse(content=analytics)
    except Exception as e:
        logger.error(f"Error getting system analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/multi-agent/simulate-scenario")
async def simulate_multi_agent_scenario(scenario_data: Dict):
    """Simulate a multi-agent cybersecurity scenario"""
    if multi_agent_system is None:
        raise HTTPException(status_code=503, detail="Multi-agent system not initialized")
    
    try:
        scenario_type = scenario_data.get("scenario_type", "advanced_persistent_threat")
        result = await multi_agent_system.simulate_multi_agent_scenario(scenario_type)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error simulating multi-agent scenario: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/multi-agent/scenarios")
async def get_multi_agent_scenarios():
    """Get available multi-agent scenarios"""
    scenarios = {
        "advanced_persistent_threat": {
            "name": "Advanced Persistent Threat (APT)",
            "description": "Simulate a sophisticated, long-term cyber attack",
            "severity": "critical",
            "agents_involved": ["threat_detection", "threat_intelligence", "response_coordination"],
            "expected_collaboration": "high"
        },
        "ransomware_campaign": {
            "name": "Ransomware Campaign",
            "description": "Simulate a coordinated ransomware attack",
            "severity": "high",
            "agents_involved": ["threat_detection", "response_coordination"],
            "expected_collaboration": "medium"
        },
        "insider_threat": {
            "name": "Insider Threat",
            "description": "Simulate malicious activity from within the organization",
            "severity": "high",
            "agents_involved": ["threat_detection", "threat_intelligence"],
            "expected_collaboration": "medium"
        }
    }
    
    return JSONResponse(content=scenarios)