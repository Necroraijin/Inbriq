"""
Data models for the Adaptive AI Firewall System
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

@dataclass
class SecurityEvent:
    """Represents a security event detected by the firewall"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    target_ip: str
    protocol: str
    description: str
    threat_score: float
    response_actions: List[str]
    status: str

@dataclass
class NetworkPacket:
    """Represents a network packet for analysis"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    flags: Dict[str, bool]
    ttl: int
    checksum: int

@dataclass
class Transaction:
    """Represents a financial transaction for monitoring"""
    transaction_id: str
    user_id: str
    amount: float
    merchant: str
    device_fingerprint: str
    geographic_location: str
    payment_method: str
    timestamp: datetime
    risk_score: float
    fraud_checks: Dict[str, bool]
    should_block: bool
    status: str

@dataclass
class ThreatDetection:
    """Represents a threat detection result"""
    threat_id: str
    timestamp: datetime
    threat_type: str
    severity: str
    threat_score: float
    source_ip: str
    target_ip: str
    protocol: str
    description: str
    confidence: float
    false_positive_probability: float

@dataclass
class ResponseAction:
    """Represents a response action taken by the system"""
    action_id: str
    timestamp: datetime
    event_id: str
    action_type: str
    priority: int
    source_ip: str
    status: str
    result: Optional[str] = None
    error_message: Optional[str] = None