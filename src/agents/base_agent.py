

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import uuid

logger = logging.getLogger(__name__)

@dataclass
class AgentMessage:
    message_id: str
    sender_id: str
    recipient_id: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime
    priority: int = 1  
    correlation_id: Optional[str] = None

@dataclass
class AgentCapability:
    capability_name: str
    description: str
    input_types: List[str]
    output_types: List[str]
    confidence_threshold: float = 0.7

@dataclass
class AgentStatus:
    agent_id: str
    status: str  
    current_task: Optional[str]
    performance_score: float
    last_activity: datetime
    messages_processed: int
    tasks_completed: int
    errors_count: int

class BaseAgent(ABC):
    
    def __init__(self, agent_id: str, agent_name: str, agent_type: str):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_type = agent_type
        self.status = "idle"
        self.current_task = None
        self.performance_score = 1.0
        self.last_activity = datetime.now()
        self.messages_processed = 0
        self.tasks_completed = 0
        self.errors_count = 0 

        self.capabilities: List[AgentCapability] = []
        self.specializations: List[str] = []

        self.message_queue: List[AgentMessage] = []
        self.subscribed_topics: List[str] = []

        self.learning_enabled = True
        self.adaptation_rate = 0.1
        self.experience_level = 1.0

        self.trusted_agents: List[str] = []
        self.collaboration_history: Dict[str, float] = {}  # agent_id -> success_rate
        
        logger.info(f" Agent {self.agent_name} ({self.agent_id}) initialized")

    @abstractmethod
    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        
        pass

    @abstractmethod
    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat data """
        pass

    async def send_message(self, recipient_id: str, message_type: str, content: Dict[str, Any], priority: int = 1):
        """Send a message to another agent"""
        message = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            message_type=message_type,
            content=content,
            timestamp=datetime.now(),
            priority=priority
        )
        
        # In a real implementation, this would go through a message broker
        
        logger.info(f"📤 {self.agent_name} -> {recipient_id}: {message_type}")
        return message

    async def receive_message(self, message: AgentMessage):
        """Receive and process a message from another agent"""
        self.messages_processed += 1
        self.last_activity = datetime.now()
        
        logger.info(f"📥 {self.agent_name} received: {message.message_type} from {message.sender_id}")
        
        # Process message based on type
        if message.message_type == "threat_analysis_request":
            await self._handle_threat_analysis_request(message)
        elif message.message_type == "collaboration_request":
            await self._handle_collaboration_request(message)
        elif message.message_type == "knowledge_share":
            await self._handle_knowledge_share(message)
        elif message.message_type == "task_delegation":
            await self._handle_task_delegation(message)
        else:
            logger.warning(f"Unknown message type: {message.message_type}")

    async def _handle_threat_analysis_request(self, message: AgentMessage):
        """Handle requests for threat analysis"""
        try:
            result = await self.analyze_threat(message.content)
            await self.send_message(
                message.sender_id,
                "threat_analysis_response",
                result,
                message.priority
            )
        except Exception as e:
            logger.error(f"Error handling threat analysis request: {e}")
            self.errors_count += 1

    async def _handle_collaboration_request(self, message: AgentMessage):
        """Handle collaboration requests from other agents"""
        try:
            
            can_help = self._can_help_with_task(message.content)
            if can_help:
                result = await self.process_task(message.content)
                await self.send_message(
                    message.sender_id,
                    "collaboration_response",
                    {"can_help": True, "result": result},
                    message.priority
                )
            else:
                await self.send_message(
                    message.sender_id,
                    "collaboration_response",
                    {"can_help": False, "reason": "Not within capabilities"},
                    message.priority
                )
        except Exception as e:
            logger.error(f"Error handling collaboration request: {e}")
            self.errors_count += 1

    async def _handle_knowledge_share(self, message: AgentMessage):
        """Handle knowledge sharing from other agents"""
        try:
            
            await self._learn_from_knowledge(message.content)
            logger.info(f" {self.agent_name} learned from {message.sender_id}")
        except Exception as e:
            logger.error(f"Error handling knowledge share: {e}")
            self.errors_count += 1

    async def _handle_task_delegation(self, message: AgentMessage):
        """Handle task delegation from coordinator agent"""
        try:
            self.status = "busy"
            self.current_task = message.content.get("task_type", "unknown")
            
            result = await self.process_task(message.content)

            await self.send_message(
                message.sender_id,
                "task_completion",
                {"task_id": message.content.get("task_id"), "result": result},
                message.priority
            )
            
            self.status = "idle"
            self.current_task = None
            self.tasks_completed += 1
            
        except Exception as e:
            logger.error(f"Error handling task delegation: {e}")
            self.errors_count += 1
            self.status = "error"

    def _can_help_with_task(self, task_data: Dict[str, Any]) -> bool:
        """Determine if this agent can help with a specific task"""
        task_type = task_data.get("task_type", "")
        required_capabilities = task_data.get("required_capabilities", [])

        for capability in required_capabilities:
            if not any(cap.capability_name == capability for cap in self.capabilities):
                return False
        
        return True

    async def _learn_from_knowledge(self, knowledge: Dict[str, Any]):
        """Learn from shared knowledge"""
        if not self.learning_enabled:
            return

        knowledge_quality = knowledge.get("quality", 0.5)
        self.experience_level += knowledge_quality * self.adaptation_rate
        self.experience_level = min(self.experience_level, 10.0)  # Cap at 10

        self.performance_score = min(1.0, self.performance_score + 0.01)

    async def request_collaboration(self, target_agent_id: str, task_data: Dict[str, Any]):
        """Request collaboration from another agent"""
        await self.send_message(
            target_agent_id,
            "collaboration_request",
            task_data,
            priority=2
        )

    async def share_knowledge(self, target_agent_id: str, knowledge: Dict[str, Any]):
        """Share knowledge with another agent"""
        await self.send_message(
            target_agent_id,
            "knowledge_share",
            knowledge,
            priority=1
        )

    def get_status(self) -> AgentStatus:
        """Get current agent status"""
        return AgentStatus(
            agent_id=self.agent_id,
            status=self.status,
            current_task=self.current_task,
            performance_score=self.performance_score,
            last_activity=self.last_activity,
            messages_processed=self.messages_processed,
            tasks_completed=self.tasks_completed,
            errors_count=self.errors_count
        )

    def get_capabilities(self) -> List[AgentCapability]:
        """Get agent capabilities"""
        return self.capabilities

    def update_trust(self, agent_id: str, success: bool):
        """Update trust level for another agent"""
        if agent_id not in self.collaboration_history:
            self.collaboration_history[agent_id] = 0.5

        if success:
            self.collaboration_history[agent_id] = min(1.0, self.collaboration_history[agent_id] + 0.1)
        else:
            self.collaboration_history[agent_id] = max(0.0, self.collaboration_history[agent_id] - 0.1)

    async def start_learning_mode(self):
        """Enable learning mode for the agent"""
        self.learning_enabled = True
        logger.info(f" {self.agent_name} entered learning mode")

    async def stop_learning_mode(self):
        """Disable learning mode for the agent"""
        self.learning_enabled = False
        logger.info(f" {self.agent_name} exited learning mode")

    def get_agent_info(self) -> Dict[str, Any]:
        """Get comprehensive agent information"""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "status": self.get_status(),
            "capabilities": [cap.__dict__ for cap in self.capabilities],
            "specializations": self.specializations,
            "trusted_agents": self.trusted_agents,
            "collaboration_history": self.collaboration_history,
            "learning_enabled": self.learning_enabled,
            "experience_level": self.experience_level,
            "performance_score": self.performance_score
        }
