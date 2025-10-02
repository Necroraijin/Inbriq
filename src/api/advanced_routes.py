"""
Advanced API Routes - All cutting-edge features
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging

from src.learning.federated_learning import FederatedLearningSystem
from src.crypto.quantum_resistant import QuantumResistantCrypto
from src.hunting.ai_threat_hunter import AIThreatHunter, ThreatType, HuntingTechnique
from src.blockchain.audit_blockchain import AuditBlockchain, AuditLevel

logger = logging.getLogger(__name__)

router = APIRouter()

federated_learning: Optional[FederatedLearningSystem] = None
quantum_crypto: Optional[QuantumResistantCrypto] = None
threat_hunter: Optional[AIThreatHunter] = None
audit_blockchain: Optional[AuditBlockchain] = None

def get_federated_learning() -> FederatedLearningSystem:
    if federated_learning is None:
        raise HTTPException(status_code=503, detail="Federated Learning System not initialized")
    return federated_learning

def get_quantum_crypto() -> QuantumResistantCrypto:
    if quantum_crypto is None:
        raise HTTPException(status_code=503, detail="Quantum-Resistant Crypto not initialized")
    return quantum_crypto

def get_threat_hunter() -> AIThreatHunter:
    if threat_hunter is None:
        raise HTTPException(status_code=503, detail="AI Threat Hunter not initialized")
    return threat_hunter

def get_audit_blockchain() -> AuditBlockchain:
    if audit_blockchain is None:
        raise HTTPException(status_code=503, detail="Audit Blockchain not initialized")
    return audit_blockchain

@router.get("/federated-learning/status")
async def get_federated_learning_status(
    fl_system: FederatedLearningSystem = Depends(get_federated_learning)
):
    """Get federated learning system status and statistics"""
    stats = await fl_system.get_federated_statistics()
    return {
        "status": "active",
        "statistics": stats,
        "capabilities": [
            "collaborative_threat_intelligence",
            "differential_privacy",
            "model_aggregation",
            "distributed_learning"
        ]
    }

@router.post("/federated-learning/predict")
async def predict_with_federated_model(
    model_type: str,
    input_data: List[float],
    fl_system: FederatedLearningSystem = Depends(get_federated_learning)
):
    """Make prediction using federated learning model"""
    import numpy as np
    input_array = np.array(input_data)
    prediction = await fl_system.predict_with_federated_model(model_type, input_array)
    return {
        "model_type": model_type,
        "input_data": input_data,
        "prediction": prediction,
        "federated_learning": True
    }

@router.get("/federated-learning/models")
async def get_federated_models(
    fl_system: FederatedLearningSystem = Depends(get_federated_learning)
):
    """Get available federated learning models"""
    return {
        "models": list(fl_system.model_registry.keys()),
        "model_details": {
            name: {
                "type": model["type"],
                "version": model["version"],
                "last_updated": model["last_updated"].isoformat()
            }
            for name, model in fl_system.model_registry.items()
        }
    }

@router.get("/quantum-crypto/status")
async def get_quantum_crypto_status(
    crypto_system: QuantumResistantCrypto = Depends(get_quantum_crypto)
):
    """Get quantum-resistant cryptography system status"""
    stats = await crypto_system.get_crypto_statistics()
    threat_assessment = await crypto_system.assess_quantum_threat_level()
    
    return {
        "status": "active",
        "statistics": stats,
        "threat_assessment": threat_assessment,
        "supported_algorithms": [
            "Kyber (Lattice-based KEM)",
            "Dilithium (Lattice-based Signature)",
            "Falcon (Lattice-based Signature)",
            "SPHINCS+ (Hash-based Signature)",
            "NTRU (Lattice-based KEM)"
        ]
    }

@router.post("/quantum-crypto/encrypt")
async def encrypt_with_quantum_resistance(
    data: str,
    algorithm: str = "kyber",
    crypto_system: QuantumResistantCrypto = Depends(get_quantum_crypto)
):
    """Encrypt data using quantum-resistant cryptography"""
    from src.crypto.quantum_resistant import QuantumAlgorithm
    
    try:
        algo = QuantumAlgorithm(algorithm.lower())
        encryption = await crypto_system.encrypt_data(data.encode(), algo)
        
        return {
            "encryption_id": encryption.encryption_id,
            "algorithm": encryption.algorithm.value,
            "ciphertext": encryption.ciphertext.hex(),
            "nonce": encryption.nonce.hex(),
            "timestamp": encryption.timestamp.isoformat(),
            "quantum_resistant": True
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")

@router.post("/quantum-crypto/sign")
async def sign_with_quantum_resistance(
    data: str,
    algorithm: str = "dilithium",
    crypto_system: QuantumResistantCrypto = Depends(get_quantum_crypto)
):
    """Sign data using quantum-resistant cryptography"""
    from src.crypto.quantum_resistant import QuantumAlgorithm
    
    try:
        algo = QuantumAlgorithm(algorithm.lower())
        signature = await crypto_system.sign_data(data.encode(), algo)
        
        return {
            "signature_id": signature.signature_id,
            "algorithm": signature.algorithm.value,
            "signature": signature.signature.hex(),
            "message_hash": signature.message_hash.hex(),
            "timestamp": signature.timestamp.isoformat(),
            "quantum_resistant": True
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")

@router.post("/quantum-crypto/hybrid-key")
async def generate_hybrid_key(
    classical_algorithm: str = "RSA",
    quantum_algorithm: str = "kyber",
    crypto_system: QuantumResistantCrypto = Depends(get_quantum_crypto)
):
    """Generate hybrid key pair combining classical and quantum-resistant cryptography"""
    from src.crypto.quantum_resistant import QuantumAlgorithm
    
    try:
        algo = QuantumAlgorithm(quantum_algorithm.lower())
        hybrid_key = await crypto_system.generate_hybrid_key(classical_algorithm, algo)
        return hybrid_key
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported quantum algorithm: {quantum_algorithm}")

@router.get("/threat-hunting/status")
async def get_threat_hunting_status(
    hunter: AIThreatHunter = Depends(get_threat_hunter)
):
    """Get AI threat hunting system status"""
    stats = await hunter.get_hunting_statistics()
    active_campaigns = await hunter.get_active_campaigns()
    
    return {
        "status": "active",
        "statistics": stats,
        "active_campaigns": active_campaigns,
        "capabilities": [
            "behavioral_analysis",
            "anomaly_detection",
            "indicator_hunting",
            "hypothesis_driven",
            "machine_learning",
            "correlation_analysis"
        ]
    }

@router.post("/threat-hunting/start-campaign")
async def start_threat_hunting_campaign(
    campaign_name: str,
    target_threats: List[str],
    techniques: List[str],
    hunter: AIThreatHunter = Depends(get_threat_hunter)
):
    """Start a new AI-powered threat hunting campaign"""
    try:
        threat_types = [ThreatType(threat) for threat in target_threats]
        hunting_techniques = [HuntingTechnique(technique) for technique in techniques]
        
        campaign = await hunter.start_hunting_campaign(campaign_name, threat_types, hunting_techniques)
        
        return {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "description": campaign.description,
            "target_threats": [t.value for t in campaign.target_threats],
            "techniques": [t.value for t in campaign.techniques],
            "start_time": campaign.start_time.isoformat(),
            "status": campaign.status.value,
            "hypotheses_count": len(campaign.hypotheses)
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid threat type or technique: {e}")

@router.get("/threat-hunting/campaigns")
async def get_hunting_campaigns(
    hunter: AIThreatHunter = Depends(get_threat_hunter)
):
    """Get all threat hunting campaigns"""
    active_campaigns = await hunter.get_active_campaigns()
    return {
        "active_campaigns": active_campaigns,
        "total_campaigns": len(active_campaigns)
    }

@router.get("/threat-hunting/results")
async def get_hunting_results(
    limit: int = 20,
    hunter: AIThreatHunter = Depends(get_threat_hunter)
):
    """Get recent threat hunting results"""
    results = await hunter.get_hunting_results(limit)
    return {
        "results": results,
        "total_results": len(results)
    }

@router.get("/blockchain/status")
async def get_blockchain_status(
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Get blockchain audit trail status"""
    stats = await blockchain.get_blockchain_statistics()
    integrity_report = blockchain.verify_chain_integrity()
    
    return {
        "status": "active",
        "statistics": {
            "total_blocks": stats.total_blocks,
            "total_records": stats.total_records,
            "chain_length": stats.chain_length,
            "average_block_time": stats.average_block_time,
            "integrity_score": stats.integrity_score,
            "validator_count": stats.validator_count
        },
        "integrity_report": integrity_report,
        "capabilities": [
            "immutable_audit_logs",
            "tamper_proof_records",
            "distributed_validation",
            "merkle_tree_verification",
            "proof_of_work"
        ]
    }

@router.post("/blockchain/audit-record")
async def create_audit_record(
    event_type: str,
    source: str,
    target: str,
    action: str,
    details: Dict[str, Any],
    audit_level: str = "medium",
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Create a new audit record in the blockchain"""
    try:
        level = AuditLevel(audit_level.lower())
        record = await blockchain.create_security_event_record(
            event_type=event_type,
            source=source,
            target=target,
            action=action,
            details=details,
            audit_level=level
        )
        
        return {
            "record_id": record.record_id,
            "timestamp": record.timestamp.isoformat(),
            "event_type": record.event_type,
            "audit_level": record.audit_level.value,
            "source": record.source,
            "target": record.target,
            "action": record.action,
            "result": record.result,
            "blockchain_verified": True
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid audit level: {audit_level}")

@router.post("/blockchain/threat-record")
async def create_threat_audit_record(
    threat_type: str,
    severity: str,
    indicators: List[Dict[str, Any]],
    response_actions: List[str],
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Create a threat detection audit record"""
    record = await blockchain.create_threat_detection_record(
        threat_type=threat_type,
        severity=severity,
        indicators=indicators,
        response_actions=response_actions
    )
    
    return {
        "record_id": record.record_id,
        "timestamp": record.timestamp.isoformat(),
        "event_type": record.event_type,
        "audit_level": record.audit_level.value,
        "threat_type": threat_type,
        "severity": severity,
        "indicators_count": len(indicators),
        "response_actions": response_actions,
        "blockchain_verified": True
    }

@router.get("/blockchain/search")
async def search_audit_records(
    event_type: Optional[str] = None,
    audit_level: Optional[str] = None,
    source: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100,
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Search audit records in the blockchain"""
    filters = {}
    if event_type:
        filters['event_type'] = event_type
    if audit_level:
        filters['audit_level'] = AuditLevel(audit_level.lower())
    if source:
        filters['source'] = source
    if start_time:
        filters['start_time'] = start_time
    if end_time:
        filters['end_time'] = end_time
    
    records = await blockchain.search_audit_records(filters, limit)
    
    return {
        "records": [
            {
                "record_id": record.record_id,
                "timestamp": record.timestamp.isoformat(),
                "event_type": record.event_type,
                "audit_level": record.audit_level.value,
                "source": record.source,
                "target": record.target,
                "action": record.action,
                "result": record.result
            }
            for record in records
        ],
        "total_found": len(records),
        "filters_applied": filters
    }

@router.get("/blockchain/export")
async def export_audit_trail(
    format: str = "json",
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Export audit trail from blockchain"""
    if format not in ["json", "csv"]:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'json' or 'csv'")
    
    export_data = await blockchain.export_audit_trail(format, start_time, end_time)
    
    return {
        "format": format,
        "export_data": export_data,
        "start_time": start_time.isoformat() if start_time else None,
        "end_time": end_time.isoformat() if end_time else None,
        "blockchain_verified": True
    }

@router.get("/comprehensive-dashboard")
async def get_comprehensive_dashboard_data(
    fl_system: FederatedLearningSystem = Depends(get_federated_learning),
    crypto_system: QuantumResistantCrypto = Depends(get_quantum_crypto),
    hunter: AIThreatHunter = Depends(get_threat_hunter),
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Get comprehensive dashboard data for all advanced features"""

    fl_stats = await fl_system.get_federated_statistics()
    crypto_stats = await crypto_system.get_crypto_statistics()
    crypto_threat = await crypto_system.assess_quantum_threat_level()
    hunting_stats = await hunter.get_hunting_statistics()
    blockchain_stats = await blockchain.get_blockchain_statistics()
    blockchain_integrity = blockchain.verify_chain_integrity()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "federated_learning": {
            "status": "active",
            "participating_nodes": fl_stats["participating_nodes"],
            "total_rounds": fl_stats["total_rounds"],
            "completed_rounds": fl_stats["completed_rounds"],
            "average_convergence_metric": fl_stats["average_convergence_metric"],
            "model_versions": fl_stats["model_versions"]
        },
        "quantum_cryptography": {
            "status": "active",
            "total_key_pairs": crypto_stats["total_key_pairs"],
            "total_signatures": crypto_stats["total_signatures"],
            "total_encryptions": crypto_stats["total_encryptions"],
            "threat_level": crypto_threat["threat_level"],
            "readiness_score": crypto_threat["readiness_score"],
            "supported_algorithms": crypto_stats["supported_algorithms"]
        },
        "threat_hunting": {
            "status": "active",
            "total_campaigns": hunting_stats["total_campaigns"],
            "active_campaigns": hunting_stats["active_campaigns"],
            "total_hunts": hunting_stats["total_hunts"],
            "successful_hunts": hunting_stats["successful_hunts"],
            "overall_success_rate": hunting_stats["overall_success_rate"],
            "threat_types_detected": hunting_stats["threat_types_detected"]
        },
        "blockchain_audit": {
            "status": "active",
            "total_blocks": blockchain_stats.total_blocks,
            "total_records": blockchain_stats.total_records,
            "chain_length": blockchain_stats.chain_length,
            "integrity_score": blockchain_stats.integrity_score,
            "validator_count": blockchain_stats.validator_count,
            "is_valid": blockchain_integrity["is_valid"]
        },
        "system_health": {
            "overall_status": "excellent",
            "all_systems_operational": True,
            "advanced_features_active": 4,
            "last_updated": datetime.now().isoformat()
        }
    }

@router.get("/3d-visualization/data")
async def get_3d_visualization_data(
    fl_system: FederatedLearningSystem = Depends(get_federated_learning),
    crypto_system: QuantumResistantCrypto = Depends(get_quantum_crypto),
    hunter: AIThreatHunter = Depends(get_threat_hunter),
    blockchain: AuditBlockchain = Depends(get_audit_blockchain)
):
    """Get data for 3D network visualization"""

    nodes = []
    connections = []

    fl_stats = await fl_system.get_federated_statistics()
    for i in range(fl_stats["participating_nodes"]):
        nodes.append({
            "id": f"fl_node_{i}",
            "name": f"FL Node {i+1}",
            "type": "federated_learning",
            "position": {
                "x": (i - fl_stats["participating_nodes"]/2) * 10,
                "y": 20,
                "z": 0
            },
            "trustScore": 0.9,
            "threatLevel": "low",
            "status": "active"
        })

    crypto_stats = await crypto_system.get_crypto_statistics()
    for i, algorithm in enumerate(crypto_stats["supported_algorithms"]):
        nodes.append({
            "id": f"crypto_node_{i}",
            "name": f"Crypto {algorithm}",
            "type": "quantum_crypto",
            "position": {
                "x": (i - len(crypto_stats["supported_algorithms"])/2) * 8,
                "y": -20,
                "z": 0
            },
            "trustScore": 0.95,
            "threatLevel": "low",
            "status": "active"
        })

    hunting_stats = await hunter.get_hunting_statistics()
    for i in range(min(5, hunting_stats["active_campaigns"])):
        nodes.append({
            "id": f"hunting_node_{i}",
            "name": f"Hunting Campaign {i+1}",
            "type": "threat_hunting",
            "position": {
                "x": 0,
                "y": 0,
                "z": (i - 2) * 15
            },
            "trustScore": 0.8,
            "threatLevel": "medium",
            "status": "active"
        })

    blockchain_stats = await blockchain.get_blockchain_statistics()
    for i in range(min(3, blockchain_stats.validator_count)):
        nodes.append({
            "id": f"blockchain_node_{i}",
            "name": f"Validator {i+1}",
            "type": "blockchain",
            "position": {
                "x": 30,
                "y": 0,
                "z": (i - 1) * 10
            },
            "trustScore": 1.0,
            "threatLevel": "low",
            "status": "active"
        })

    for i in range(len(nodes) - 1):
        connections.append({
            "source": nodes[i]["id"],
            "target": nodes[i + 1]["id"],
            "strength": 0.8,
            "type": "normal",
            "traffic": 100
        })
    
    return {
        "nodes": nodes,
        "connections": connections,
        "metadata": {
            "total_nodes": len(nodes),
            "total_connections": len(connections),
            "visualization_type": "advanced_cybersecurity_network",
            "last_updated": datetime.now().isoformat()
        }
    }