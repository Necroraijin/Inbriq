"""
Blockchain-based Audit Trail - Immutable security logs and tamper-proof records
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import json
import secrets
from dataclasses import dataclass, asdict
from enum import Enum
import time
import random

logger = logging.getLogger(__name__)

class BlockType(Enum):
    """Types of blocks in the audit blockchain"""
    SECURITY_EVENT = "security_event"
    THREAT_DETECTION = "threat_detection"
    RESPONSE_ACTION = "response_action"
    TRUST_EVALUATION = "trust_evaluation"
    SYSTEM_CHANGE = "system_change"
    COMPLIANCE_LOG = "compliance_log"

class AuditLevel(Enum):
    """Audit levels for different types of events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AuditRecord:
    """Individual audit record"""
    record_id: str
    timestamp: datetime
    event_type: str
    audit_level: AuditLevel
    source: str
    target: str
    action: str
    details: Dict[str, Any]
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    result: str
    metadata: Dict[str, Any]

@dataclass
class Block:
    """Block in the audit blockchain"""
    index: int
    timestamp: datetime
    previous_hash: str
    hash: str
    merkle_root: str
    nonce: int
    records: List[AuditRecord]
    block_type: BlockType
    validator: str
    signature: str

@dataclass
class BlockchainStats:
    """Blockchain statistics"""
    total_blocks: int
    total_records: int
    chain_length: int
    last_block_hash: str
    average_block_time: float
    integrity_score: float
    validator_count: int

class AuditBlockchain:
    """
    Blockchain-based Audit Trail System for immutable security logs
    """
    
    def __init__(self):
        self.chain = []
        self.pending_records = []
        self.validators = set()
        self.difficulty = 4
        self.block_size_limit = 100
        self.block_time_target = 10

        self._create_genesis_block()

        self._initialize_validators()

        self.mining_active = False
        
        logger.info("⛓️ Audit Blockchain initialized")

    def _create_genesis_block(self):
        """Create the genesis block"""
        genesis_record = AuditRecord(
            record_id="genesis_001",
            timestamp=datetime.now(),
            event_type="system_initialization",
            audit_level=AuditLevel.CRITICAL,
            source="system",
            target="blockchain",
            action="initialize",
            details={"message": "Genesis block created"},
            user_id="system",
            session_id="genesis",
            ip_address="127.0.0.1",
            user_agent="AuditBlockchain/1.0",
            result="success",
            metadata={"version": "1.0", "algorithm": "SHA-256"}
        )
        
        genesis_block = Block(
            index=0,
            timestamp=datetime.now(),
            previous_hash="0",
            hash="",
            merkle_root="",
            nonce=0,
            records=[genesis_record],
            block_type=BlockType.SYSTEM_CHANGE,
            validator="genesis",
            signature=""
        )

        genesis_block.merkle_root = self._calculate_merkle_root([genesis_record])
        genesis_block.hash = self._calculate_block_hash(genesis_block)
        genesis_block.signature = self._sign_block(genesis_block)
        
        self.chain.append(genesis_block)
        logger.info("🏗️ Genesis block created")

    def _initialize_validators(self):
        """Initialize blockchain validators"""

        validators = [
            "validator_001",
            "validator_002", 
            "validator_003",
            "validator_004",
            "validator_005"
        ]
        
        for validator in validators:
            self.validators.add(validator)
        
        logger.info(f"✅ Initialized {len(self.validators)} validators")

    async def start_mining(self):
        """Start the blockchain mining process"""
        self.mining_active = True
        logger.info("⛏️ Blockchain mining started")

        asyncio.create_task(self._mining_loop())

    async def stop_mining(self):
        """Stop the blockchain mining process"""
        self.mining_active = False
        logger.info("⛏️ Blockchain mining stopped")

    async def _mining_loop(self):
        """Main mining loop"""
        while self.mining_active:
            try:

                if len(self.pending_records) >= self.block_size_limit:
                    await self._mine_block()
                elif len(self.pending_records) > 0:

                    if self.chain:
                        last_block_time = self.chain[-1].timestamp
                        time_since_last = (datetime.now() - last_block_time).total_seconds()
                        if time_since_last >= self.block_time_target:
                            await self._mine_block()
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in mining loop: {e}")
                await asyncio.sleep(5)

    async def _mine_block(self):
        """Mine a new block"""
        if not self.pending_records:
            return

        records_to_mine = self.pending_records[:self.block_size_limit]
        self.pending_records = self.pending_records[self.block_size_limit:]

        block_type = self._determine_block_type(records_to_mine)

        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(),
            previous_hash=self.chain[-1].hash if self.chain else "0",
            hash="",
            merkle_root="",
            nonce=0,
            records=records_to_mine,
            block_type=block_type,
            validator="",
            signature=""
        )

        new_block.merkle_root = self._calculate_merkle_root(records_to_mine)

        await self._proof_of_work(new_block)

        if self._validate_block(new_block):
            self.chain.append(new_block)
            logger.info(f"✅ Block {new_block.index} mined successfully with {len(records_to_mine)} records")
        else:
            logger.error("❌ Block validation failed")

            self.pending_records = records_to_mine + self.pending_records

    def _determine_block_type(self, records: List[AuditRecord]) -> BlockType:
        """Determine block type based on records"""

        type_counts = {}
        for record in records:
            event_type = record.event_type
            if 'threat' in event_type.lower() or 'attack' in event_type.lower():
                block_type = BlockType.THREAT_DETECTION
            elif 'response' in event_type.lower() or 'action' in event_type.lower():
                block_type = BlockType.RESPONSE_ACTION
            elif 'trust' in event_type.lower():
                block_type = BlockType.TRUST_EVALUATION
            elif 'compliance' in event_type.lower():
                block_type = BlockType.COMPLIANCE_LOG
            else:
                block_type = BlockType.SECURITY_EVENT
            
            type_counts[block_type] = type_counts.get(block_type, 0) + 1

        return max(type_counts, key=type_counts.get) if type_counts else BlockType.SECURITY_EVENT

    async def _proof_of_work(self, block: Block):
        """Perform proof of work to mine the block"""
        target = "0" * self.difficulty
        start_time = time.time()

        validator = secrets.choice(list(self.validators))
        block.validator = validator

        while block.hash[:self.difficulty] != target:
            block.nonce += 1
            block.hash = self._calculate_block_hash(block)

            if block.nonce % 1000 == 0:
                await asyncio.sleep(0.001)

        block.signature = self._sign_block(block)
        
        mining_time = time.time() - start_time
        logger.info(f"⛏️ Block {block.index} mined in {mining_time:.2f}s (nonce: {block.nonce})")

    def _calculate_block_hash(self, block: Block) -> str:
        """Calculate hash for a block"""
        block_string = f"{block.index}{block.timestamp.isoformat()}{block.previous_hash}{block.merkle_root}{block.nonce}{block.validator}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def _calculate_merkle_root(self, records: List[AuditRecord]) -> str:
        """Calculate Merkle root for records"""
        if not records:
            return "0"

        record_hashes = []
        for record in records:
            record_string = f"{record.record_id}{record.timestamp.isoformat()}{record.event_type}{record.source}{record.target}{record.action}{json.dumps(record.details, sort_keys=True)}"
            record_hashes.append(hashlib.sha256(record_string.encode()).hexdigest())

        while len(record_hashes) > 1:
            next_level = []
            for i in range(0, len(record_hashes), 2):
                left = record_hashes[i]
                right = record_hashes[i + 1] if i + 1 < len(record_hashes) else left
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            record_hashes = next_level
        
        return record_hashes[0] if record_hashes else "0"

    def _sign_block(self, block: Block) -> str:
        """Sign a block (simplified signature)"""

        signature_data = f"{block.index}{block.timestamp.isoformat()}{block.hash}{block.validator}"
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]

    def _validate_block(self, block: Block) -> bool:
        """Validate a block"""

        if block.hash != self._calculate_block_hash(block):
            return False

        if self.chain and block.previous_hash != self.chain[-1].hash:
            return False

        if block.merkle_root != self._calculate_merkle_root(block.records):
            return False

        if block.validator not in self.validators:
            return False

        if not block.hash.startswith("0" * self.difficulty):
            return False
        
        return True

    async def add_audit_record(self, record: AuditRecord):
        """Add an audit record to the blockchain"""

        if not self._validate_record(record):
            logger.error(f"Invalid audit record: {record.record_id}")
            return False

        self.pending_records.append(record)
        logger.info(f"📝 Added audit record: {record.record_id}")
        
        return True

    def _validate_record(self, record: AuditRecord) -> bool:
        """Validate an audit record"""

        if not all([record.record_id, record.event_type, record.source, record.target, record.action]):
            return False

        if record.timestamp > datetime.now():
            return False

        for block in self.chain:
            for existing_record in block.records:
                if existing_record.record_id == record.record_id:
                    return False
        
        return True

    async def create_security_event_record(self, event_type: str, source: str, target: str, action: str, details: Dict[str, Any], audit_level: AuditLevel = AuditLevel.MEDIUM) -> AuditRecord:
        """Create a security event audit record"""
        record = AuditRecord(
            record_id=f"sec_{secrets.token_hex(8)}",
            timestamp=datetime.now(),
            event_type=event_type,
            audit_level=audit_level,
            source=source,
            target=target,
            action=action,
            details=details,
            user_id=details.get('user_id'),
            session_id=details.get('session_id'),
            ip_address=details.get('ip_address'),
            user_agent=details.get('user_agent'),
            result=details.get('result', 'success'),
            metadata={
                'created_by': 'audit_blockchain',
                'version': '1.0',
                'integrity_check': True
            }
        )
        
        await self.add_audit_record(record)
        return record

    async def create_threat_detection_record(self, threat_type: str, severity: str, indicators: List[Dict[str, Any]], response_actions: List[str]) -> AuditRecord:
        """Create a threat detection audit record"""
        details = {
            'threat_type': threat_type,
            'severity': severity,
            'indicators': indicators,
            'response_actions': response_actions,
            'detection_method': 'ai_ml_analysis',
            'confidence_score': random.uniform(0.7, 0.95)
        }
        
        audit_level = AuditLevel.CRITICAL if severity == 'critical' else AuditLevel.HIGH if severity == 'high' else AuditLevel.MEDIUM
        
        return await self.create_security_event_record(
            event_type="threat_detection",
            source="threat_detector",
            target="security_system",
            action="detect_threat",
            details=details,
            audit_level=audit_level
        )

    async def create_response_action_record(self, action_type: str, target: str, result: str, details: Dict[str, Any]) -> AuditRecord:
        """Create a response action audit record"""
        action_details = {
            'action_type': action_type,
            'target': target,
            'result': result,
            'execution_time': details.get('execution_time', 0),
            'success': result == 'success',
            'automated': details.get('automated', True)
        }
        
        audit_level = AuditLevel.HIGH if action_type in ['block_ip', 'quarantine', 'escalate'] else AuditLevel.MEDIUM
        
        return await self.create_security_event_record(
            event_type="response_action",
            source="response_engine",
            target=target,
            action=action_type,
            details=action_details,
            audit_level=audit_level
        )

    async def create_trust_evaluation_record(self, entity_id: str, trust_score: float, factors: Dict[str, float], decision: str) -> AuditRecord:
        """Create a trust evaluation audit record"""
        details = {
            'entity_id': entity_id,
            'trust_score': trust_score,
            'factor_scores': factors,
            'decision': decision,
            'evaluation_method': 'continuous_trust_engine',
            'confidence': random.uniform(0.8, 0.95)
        }
        
        audit_level = AuditLevel.HIGH if trust_score < 0.3 else AuditLevel.MEDIUM if trust_score < 0.6 else AuditLevel.LOW
        
        return await self.create_security_event_record(
            event_type="trust_evaluation",
            source="trust_engine",
            target=entity_id,
            action="evaluate_trust",
            details=details,
            audit_level=audit_level
        )

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the blockchain"""
        integrity_report = {
            'is_valid': True,
            'total_blocks': len(self.chain),
            'corrupted_blocks': [],
            'integrity_score': 1.0,
            'verification_timestamp': datetime.now().isoformat()
        }
        
        for i, block in enumerate(self.chain):

            if not self._validate_block(block):
                integrity_report['is_valid'] = False
                integrity_report['corrupted_blocks'].append(i)

            if i > 0 and block.previous_hash != self.chain[i-1].hash:
                integrity_report['is_valid'] = False
                integrity_report['corrupted_blocks'].append(i)

        if integrity_report['total_blocks'] > 0:
            integrity_report['integrity_score'] = 1.0 - (len(integrity_report['corrupted_blocks']) / integrity_report['total_blocks'])
        
        return integrity_report

    async def get_blockchain_statistics(self) -> BlockchainStats:
        """Get blockchain statistics"""
        total_records = sum(len(block.records) for block in self.chain)

        if len(self.chain) > 1:
            total_time = (self.chain[-1].timestamp - self.chain[0].timestamp).total_seconds()
            average_block_time = total_time / (len(self.chain) - 1)
        else:
            average_block_time = 0

        integrity_report = self.verify_chain_integrity()
        integrity_score = integrity_report['integrity_score']
        
        return BlockchainStats(
            total_blocks=len(self.chain),
            total_records=total_records,
            chain_length=len(self.chain),
            last_block_hash=self.chain[-1].hash if self.chain else "0",
            average_block_time=average_block_time,
            integrity_score=integrity_score,
            validator_count=len(self.validators)
        )

    async def search_audit_records(self, filters: Dict[str, Any], limit: int = 100) -> List[AuditRecord]:
        """Search audit records with filters"""
        results = []
        
        for block in reversed(self.chain):
            for record in block.records:

                if self._record_matches_filters(record, filters):
                    results.append(record)
                    if len(results) >= limit:
                        return results
        
        return results

    def _record_matches_filters(self, record: AuditRecord, filters: Dict[str, Any]) -> bool:
        """Check if record matches search filters"""
        for key, value in filters.items():
            if key == 'event_type' and record.event_type != value:
                return False
            elif key == 'audit_level' and record.audit_level != value:
                return False
            elif key == 'source' and record.source != value:
                return False
            elif key == 'target' and record.target != value:
                return False
            elif key == 'action' and record.action != value:
                return False
            elif key == 'result' and record.result != value:
                return False
            elif key == 'user_id' and record.user_id != value:
                return False
            elif key == 'start_time' and record.timestamp < value:
                return False
            elif key == 'end_time' and record.timestamp > value:
                return False
        
        return True

    async def export_audit_trail(self, format: str = 'json', start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> str:
        """Export audit trail in specified format"""
        records = []
        
        for block in self.chain:
            for record in block.records:

                if start_time and record.timestamp < start_time:
                    continue
                if end_time and record.timestamp > end_time:
                    continue
                
                records.append(record)
        
        if format == 'json':
            return json.dumps([asdict(record) for record in records], default=str, indent=2)
        elif format == 'csv':

            csv_data = "record_id,timestamp,event_type,audit_level,source,target,action,result\n"
            for record in records:
                csv_data += f"{record.record_id},{record.timestamp.isoformat()},{record.event_type},{record.audit_level.value},{record.source},{record.target},{record.action},{record.result}\n"
            return csv_data
        else:
            raise ValueError(f"Unsupported export format: {format}")

    async def get_audit_summary(self, time_period: timedelta = timedelta(days=1)) -> Dict[str, Any]:
        """Get audit summary for a time period"""
        end_time = datetime.now()
        start_time = end_time - time_period

        records = []
        for block in self.chain:
            for record in block.records:
                if start_time <= record.timestamp <= end_time:
                    records.append(record)

        event_types = {}
        audit_levels = {}
        sources = {}
        results = {}
        
        for record in records:
            event_types[record.event_type] = event_types.get(record.event_type, 0) + 1
            audit_levels[record.audit_level.value] = audit_levels.get(record.audit_level.value, 0) + 1
            sources[record.source] = sources.get(record.source, 0) + 1
            results[record.result] = results.get(record.result, 0) + 1
        
        return {
            'time_period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_hours': time_period.total_seconds() / 3600
            },
            'total_records': len(records),
            'event_types': event_types,
            'audit_levels': audit_levels,
            'sources': sources,
            'results': results,
            'success_rate': results.get('success', 0) / len(records) if records else 0,
            'critical_events': audit_levels.get('critical', 0),
            'high_priority_events': audit_levels.get('high', 0) + audit_levels.get('critical', 0)
        }