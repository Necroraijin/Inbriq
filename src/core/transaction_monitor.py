"""Transaction monitoring"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import random
import json

logger = logging.getLogger(__name__)

class TransactionMonitor:
    """
    Specialized monitor for financial transactions and fraud detection
    """
    
    def __init__(self):
        self.transaction_history = []
        self.fraud_patterns = {}
        self.user_profiles = {}
        self.merchant_risk_scores = {}
        self.geographic_patterns = {}

        self._initialize_demo_data()
        
        logger.info("Transaction Monitor initialized")

    def _initialize_demo_data(self):
        """Initialize demo data for hackathon presentation"""

        self.merchant_risk_scores = {
            "amazon.com": 0.1,
            "google.com": 0.1,
            "paypal.com": 0.2,
            "stripe.com": 0.2,
            "unknown-merchant.com": 0.8,
            "suspicious-site.com": 0.9
        }

        self.user_profiles = {
            "user_001": {
                "avg_transaction_amount": 150.0,
                "typical_merchants": ["amazon.com", "google.com"],
                "usual_time_range": (9, 17),
                "geographic_region": "US",
                "device_fingerprint": "device_123",
                "risk_score": 0.1
            },
            "user_002": {
                "avg_transaction_amount": 75.0,
                "typical_merchants": ["paypal.com", "stripe.com"],
                "usual_time_range": (18, 23),
                "geographic_region": "EU",
                "device_fingerprint": "device_456",
                "risk_score": 0.2
            }
        }

    async def monitor_transaction(self, transaction_data: Dict) -> Dict:
        """
        Monitor a financial transaction for suspicious activity
        """
        try:

            transaction_id = transaction_data.get("id", f"txn_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            user_id = transaction_data.get("user_id", "unknown")
            amount = transaction_data.get("amount", 0.0)
            merchant = transaction_data.get("merchant", "unknown")
            timestamp = datetime.now()

            fraud_checks = await self._perform_fraud_checks(transaction_data)

            risk_score = self._calculate_risk_score(transaction_data, fraud_checks)

            should_block = risk_score > 0.8

            transaction_record = {
                "transaction_id": transaction_id,
                "user_id": user_id,
                "amount": amount,
                "merchant": merchant,
                "timestamp": timestamp.isoformat(),
                "risk_score": risk_score,
                "fraud_checks": fraud_checks,
                "should_block": should_block,
                "status": "blocked" if should_block else "approved"
            }

            self.transaction_history.append(transaction_record)

            if len(self.transaction_history) > 1000:
                self.transaction_history = self.transaction_history[-1000:]

            self._update_user_profile(user_id, transaction_data)
            
            logger.info(f"Transaction {transaction_id} monitored - Risk: {risk_score:.3f}, Blocked: {should_block}")
            
            return transaction_record
            
        except Exception as e:
            logger.error(f"Error monitoring transaction: {e}")
            return {
                "transaction_id": transaction_data.get("id", "unknown"),
                "error": str(e),
                "status": "error"
            }

    async def _perform_fraud_checks(self, transaction_data: Dict) -> Dict:
        """Perform various fraud detection checks"""
        checks = {
            "amount_anomaly": False,
            "velocity_check": False,
            "geographic_anomaly": False,
            "merchant_risk": False,
            "device_fingerprint": False,
            "time_anomaly": False,
            "pattern_anomaly": False
        }
        
        try:
            user_id = transaction_data.get("user_id", "unknown")
            amount = transaction_data.get("amount", 0.0)
            merchant = transaction_data.get("merchant", "unknown")
            device_fingerprint = transaction_data.get("device_fingerprint", "unknown")
            geographic_location = transaction_data.get("geographic_location", "unknown")
            timestamp = datetime.now()

            if user_id in self.user_profiles:
                user_profile = self.user_profiles[user_id]
                avg_amount = user_profile["avg_transaction_amount"]
                if amount > avg_amount * 3:
                    checks["amount_anomaly"] = True

            recent_transactions = [
                tx for tx in self.transaction_history[-10:]
                if tx["user_id"] == user_id and
                datetime.fromisoformat(tx["timestamp"]) > timestamp - timedelta(minutes=10)
            ]
            if len(recent_transactions) > 5:
                checks["velocity_check"] = True

            if user_id in self.user_profiles:
                user_profile = self.user_profiles[user_id]
                if geographic_location != user_profile["geographic_region"]:
                    checks["geographic_anomaly"] = True

            merchant_risk = self.merchant_risk_scores.get(merchant, 0.5)
            if merchant_risk > 0.7:
                checks["merchant_risk"] = True

            if user_id in self.user_profiles:
                user_profile = self.user_profiles[user_id]
                if device_fingerprint != user_profile["device_fingerprint"]:
                    checks["device_fingerprint"] = True

            if user_id in self.user_profiles:
                user_profile = self.user_profiles[user_id]
                current_hour = timestamp.hour
                usual_range = user_profile["usual_time_range"]
                if not (usual_range[0] <= current_hour <= usual_range[1]):
                    checks["time_anomaly"] = True

            if random.random() < 0.1:
                checks["pattern_anomaly"] = True
            
        except Exception as e:
            logger.error(f"Error performing fraud checks: {e}")
        
        return checks

    def _calculate_risk_score(self, transaction_data: Dict, fraud_checks: Dict) -> float:
        """Calculate overall risk score for transaction"""
        try:
            base_score = 0.0

            check_weights = {
                "amount_anomaly": 0.3,
                "velocity_check": 0.2,
                "geographic_anomaly": 0.15,
                "merchant_risk": 0.15,
                "device_fingerprint": 0.1,
                "time_anomaly": 0.05,
                "pattern_anomaly": 0.05
            }

            for check, weight in check_weights.items():
                if fraud_checks.get(check, False):
                    base_score += weight

            merchant = transaction_data.get("merchant", "unknown")
            merchant_risk = self.merchant_risk_scores.get(merchant, 0.5)
            base_score += merchant_risk * 0.2

            user_id = transaction_data.get("user_id", "unknown")
            if user_id in self.user_profiles:
                user_risk = self.user_profiles[user_id]["risk_score"]
                base_score += user_risk * 0.1

            base_score += random.uniform(-0.1, 0.1)

            return max(0.0, min(1.0, base_score))
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.5

    def _update_user_profile(self, user_id: str, transaction_data: Dict):
        """Update user profile based on transaction"""
        try:
            if user_id not in self.user_profiles:
                self.user_profiles[user_id] = {
                    "avg_transaction_amount": transaction_data.get("amount", 0.0),
                    "typical_merchants": [transaction_data.get("merchant", "unknown")],
                    "usual_time_range": (datetime.now().hour, datetime.now().hour),
                    "geographic_region": transaction_data.get("geographic_location", "unknown"),
                    "device_fingerprint": transaction_data.get("device_fingerprint", "unknown"),
                    "risk_score": 0.1
                }
            else:

                profile = self.user_profiles[user_id]
                current_avg = profile["avg_transaction_amount"]
                new_amount = transaction_data.get("amount", 0.0)
                profile["avg_transaction_amount"] = (current_avg + new_amount) / 2

                merchant = transaction_data.get("merchant", "unknown")
                if merchant not in profile["typical_merchants"]:
                    profile["typical_merchants"].append(merchant)

                    if len(profile["typical_merchants"]) > 10:
                        profile["typical_merchants"] = profile["typical_merchants"][-10:]
                
        except Exception as e:
            logger.error(f"Error updating user profile: {e}")

    def get_transaction_statistics(self) -> Dict:
        """Get transaction monitoring statistics"""
        try:
            total_transactions = len(self.transaction_history)
            blocked_transactions = len([tx for tx in self.transaction_history if tx.get("should_block", False)])
            high_risk_transactions = len([tx for tx in self.transaction_history if tx.get("risk_score", 0) > 0.7])

            avg_risk_score = 0.0
            if total_transactions > 0:
                total_risk = sum(tx.get("risk_score", 0) for tx in self.transaction_history)
                avg_risk_score = total_risk / total_transactions

            fraud_check_stats = {}
            for check_name in ["amount_anomaly", "velocity_check", "geographic_anomaly", 
                             "merchant_risk", "device_fingerprint", "time_anomaly", "pattern_anomaly"]:
                count = sum(1 for tx in self.transaction_history 
                           if tx.get("fraud_checks", {}).get(check_name, False))
                fraud_check_stats[check_name] = count
            
            return {
                "total_transactions": total_transactions,
                "blocked_transactions": blocked_transactions,
                "high_risk_transactions": high_risk_transactions,
                "block_rate": (blocked_transactions / total_transactions * 100) if total_transactions > 0 else 0,
                "average_risk_score": avg_risk_score,
                "fraud_check_statistics": fraud_check_stats,
                "monitored_users": len(self.user_profiles),
                "monitored_merchants": len(self.merchant_risk_scores)
            }
            
        except Exception as e:
            logger.error(f"Error getting transaction statistics: {e}")
            return {}

    def get_recent_transactions(self, limit: int = 20) -> List[Dict]:
        """Get recent transactions"""
        try:
            return self.transaction_history[-limit:] if self.transaction_history else []
        except Exception as e:
            logger.error(f"Error getting recent transactions: {e}")
            return []

    def get_high_risk_transactions(self, limit: int = 10) -> List[Dict]:
        """Get high-risk transactions"""
        try:
            high_risk = [tx for tx in self.transaction_history if tx.get("risk_score", 0) > 0.7]
            return high_risk[-limit:] if high_risk else []
        except Exception as e:
            logger.error(f"Error getting high-risk transactions: {e}")
            return []

    def get_user_profile(self, user_id: str) -> Optional[Dict]:
        """Get user profile"""
        return self.user_profiles.get(user_id)

    def update_merchant_risk_score(self, merchant: str, risk_score: float):
        """Update merchant risk score"""
        self.merchant_risk_scores[merchant] = max(0.0, min(1.0, risk_score))
        logger.info(f"Updated merchant {merchant} risk score to {risk_score}")

    def add_fraud_pattern(self, pattern_name: str, pattern_data: Dict):
        """Add a new fraud pattern"""
        self.fraud_patterns[pattern_name] = pattern_data
        logger.info(f"Added fraud pattern: {pattern_name}")

    def get_fraud_patterns(self) -> Dict:
        """Get all fraud patterns"""
        return self.fraud_patterns

    async def generate_demo_transaction(self) -> Dict:
        """Generate a demo transaction for testing"""
        users = list(self.user_profiles.keys()) + ["demo_user"]
        merchants = list(self.merchant_risk_scores.keys())

        user_id = random.choice(users)
        merchant = random.choice(merchants)

        transaction_data = {
            "id": f"demo_txn_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "user_id": user_id,
            "amount": random.uniform(10.0, 1000.0),
            "merchant": merchant,
            "device_fingerprint": f"device_{random.randint(100, 999)}",
            "geographic_location": random.choice(["US", "EU", "AS", "unknown"]),
            "payment_method": random.choice(["credit_card", "debit_card", "paypal", "crypto"]),
            "timestamp": datetime.now().isoformat()
        }

        result = await self.monitor_transaction(transaction_data)
        
        return result

    def get_merchant_risk_scores(self) -> Dict:
        """Get all merchant risk scores"""
        return self.merchant_risk_scores

    def get_user_profiles(self) -> Dict:
        """Get all user profiles"""
        return self.user_profiles

    def export_transaction_data(self, format: str = "json") -> str:
        """Export transaction data in specified format"""
        try:
            if format.lower() == "json":
                return json.dumps({
                    "transactions": self.transaction_history,
                    "user_profiles": self.user_profiles,
                    "merchant_risk_scores": self.merchant_risk_scores,
                    "fraud_patterns": self.fraud_patterns,
                    "export_timestamp": datetime.now().isoformat()
                }, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting transaction data: {e}")
            return ""

    def import_transaction_data(self, data: str, format: str = "json"):
        """Import transaction data from specified format"""
        try:
            if format.lower() == "json":
                imported_data = json.loads(data)
                
                if "transactions" in imported_data:
                    self.transaction_history = imported_data["transactions"]
                if "user_profiles" in imported_data:
                    self.user_profiles.update(imported_data["user_profiles"])
                if "merchant_risk_scores" in imported_data:
                    self.merchant_risk_scores.update(imported_data["merchant_risk_scores"])
                if "fraud_patterns" in imported_data:
                    self.fraud_patterns.update(imported_data["fraud_patterns"])
                
                logger.info("Transaction data imported successfully")
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            logger.error(f"Error importing transaction data: {e}")

    def clear_old_data(self, days: int = 30):
        """Clear transaction data older than specified days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)

            self.transaction_history = [
                tx for tx in self.transaction_history
                if datetime.fromisoformat(tx["timestamp"]) > cutoff_date
            ]
            
            logger.info(f"Cleared transaction data older than {days} days")
            
        except Exception as e:
            logger.error(f"Error clearing old data: {e}")

    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            "is_monitoring": True,
            "total_transactions": len(self.transaction_history),
            "monitored_users": len(self.user_profiles),
            "monitored_merchants": len(self.merchant_risk_scores),
            "fraud_patterns": len(self.fraud_patterns),
            "last_update": datetime.now().isoformat()
        }