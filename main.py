"""
Inbriq - Intelligent Network Security Platform
"""

import asyncio
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import json
from datetime import datetime
import logging

from src.core.firewall_engine import FirewallEngine
from src.core.threat_detector import ThreatDetector
from src.core.response_engine import ResponseEngine
from src.core.network_monitor import NetworkMonitor
from src.core.transaction_monitor import TransactionMonitor
from src.agents.multi_agent_system import MultiAgentCybersecuritySystem
from src.trust.trust_engine import ContinuousTrustEngine
from src.profiling.behavioral_profiler import AdvancedBehavioralProfiler
from src.audit.explainability_engine import EnhancedExplainabilityEngine
from src.optimization.performance_engine import PerformanceOptimizationEngine
from src.learning.federated_learning import FederatedLearningSystem
from src.crypto.quantum_resistant import QuantumResistantCrypto
from src.hunting.ai_threat_hunter import AIThreatHunter
from src.blockchain.audit_blockchain import AuditBlockchain
from src.api.routes import router
from src.api.enhanced_routes import router as enhanced_router
from src.api.advanced_routes import router as advanced_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    global firewall_engine, threat_detector, response_engine, network_monitor, transaction_monitor, multi_agent_system
    global trust_engine, behavioral_profiler, explainability_engine, performance_engine
    global federated_learning, quantum_crypto, threat_hunter, audit_blockchain
    
    logger.info("Starting firewall system...")

    threat_detector = ThreatDetector()
    response_engine = ResponseEngine()
    network_monitor = NetworkMonitor()
    transaction_monitor = TransactionMonitor()
    firewall_engine = FirewallEngine(threat_detector, response_engine)

    trust_engine = ContinuousTrustEngine()
    behavioral_profiler = AdvancedBehavioralProfiler()
    explainability_engine = EnhancedExplainabilityEngine()
    performance_engine = PerformanceOptimizationEngine()

    federated_learning = FederatedLearningSystem()
    quantum_crypto = QuantumResistantCrypto()
    threat_hunter = AIThreatHunter()
    audit_blockchain = AuditBlockchain()

    multi_agent_system = MultiAgentCybersecuritySystem()
    await multi_agent_system.start_system()

    await performance_engine.start_performance_monitoring()
    await federated_learning.start_federated_learning()
    await audit_blockchain.start_mining()
    
    logger.info("All systems initialized!")

    import src.api.routes as routes_module
    routes_module.firewall_engine = firewall_engine
    routes_module.threat_detector = threat_detector
    routes_module.response_engine = response_engine
    routes_module.network_monitor = network_monitor
    routes_module.transaction_monitor = transaction_monitor
    routes_module.multi_agent_system = multi_agent_system
    routes_module.trust_engine = trust_engine
    routes_module.behavioral_profiler = behavioral_profiler
    routes_module.explainability_engine = explainability_engine
    routes_module.performance_engine = performance_engine

    import src.api.enhanced_routes as enhanced_routes_module
    enhanced_routes_module.trust_engine = trust_engine
    enhanced_routes_module.behavioral_profiler = behavioral_profiler
    enhanced_routes_module.explainability_engine = explainability_engine
    enhanced_routes_module.performance_engine = performance_engine

    import src.api.advanced_routes as advanced_routes_module
    advanced_routes_module.federated_learning = federated_learning
    advanced_routes_module.quantum_crypto = quantum_crypto
    advanced_routes_module.threat_hunter = threat_hunter
    advanced_routes_module.audit_blockchain = audit_blockchain

    asyncio.create_task(firewall_engine.start_monitoring())
    
    logger.info("Firewall system ready!")
    
    yield

    logger.info("Shutting down system...")
    if multi_agent_system:
        await multi_agent_system.stop_system()
    if firewall_engine:
        firewall_engine.stop_monitoring()
    if performance_engine:
        await performance_engine.stop_performance_monitoring()
    if federated_learning:
        await federated_learning.stop_mining()
    if audit_blockchain:
        await audit_blockchain.stop_mining()

app = FastAPI(
    title="Inbriq",
    description="Intelligent Network Security Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.include_router(router, prefix="/api")
app.include_router(enhanced_router, prefix="/api/enhanced")
app.include_router(advanced_router, prefix="/api/advanced")

app.mount("/static", StaticFiles(directory="web"), name="static")

firewall_engine = None
threat_detector = None
response_engine = None
network_monitor = None
transaction_monitor = None
multi_agent_system = None
connected_clients = []

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:

                self.active_connections.remove(connection)

manager = ConnectionManager()

@app.get("/")
async def get_dashboard():
    """Serve the main dashboard"""
    with open("web/dashboard.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/3d")
async def get_3d_dashboard():
    """Serve the 3D visualization dashboard"""
    with open("web/3d-dashboard.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:

            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "ping":
                await manager.send_personal_message(
                    json.dumps({"type": "pong", "timestamp": datetime.now().isoformat()}),
                    websocket
                )
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def broadcast_alert(alert_data):
    """Broadcast security alerts to all connected clients"""
    await manager.broadcast(json.dumps({
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.now().isoformat()
    }))

app.broadcast_alert = broadcast_alert

if __name__ == "__main__":
    print("Inbriq - Intelligent Network Security Platform")
    print("=" * 50)
    print("Starting server on http://localhost:8000")
    print("Dashboard available at http://localhost:8000")
    print("API documentation at http://localhost:8000/docs")
    print("=" * 50)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )