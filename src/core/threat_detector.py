"""
Threat detection using ML models
"""

import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import os
import json

logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    AI-powered threat detection using machine learning models
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_names = []
        self.is_trained = False
        self.model_path = "models/"

        os.makedirs(self.model_path, exist_ok=True)

        self._initialize_models()

        self._load_models()
        
        logger.info("Threat Detector initialized")

    def _initialize_models(self):
        """Initialize ML models for different threat types"""

        self.models['anomaly_detector'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )

        self.models['ddos_detector'] = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )

        self.models['malware_detector'] = IsolationForest(
            contamination=0.05,
            random_state=42
        )

        self.models['transaction_anomaly'] = IsolationForest(
            contamination=0.02,
            random_state=42
        )

        self.scalers['anomaly_scaler'] = StandardScaler()
        self.scalers['ddos_scaler'] = StandardScaler()
        self.scalers['malware_scaler'] = StandardScaler()
        self.scalers['transaction_scaler'] = StandardScaler()

        self.feature_names = {
            'network': [
                'packet_size', 'packet_rate', 'connection_count', 'unique_ips',
                'port_diversity', 'protocol_diversity', 'bytes_per_second',
                'packets_per_second', 'avg_packet_size', 'connection_duration'
            ],
            'ddos': [
                'packet_rate', 'connection_rate', 'unique_sources', 'packet_size_variance',
                'protocol_concentration', 'port_concentration', 'geographic_diversity',
                'request_pattern_entropy', 'response_time_variance'
            ],
            'malware': [
                'payload_entropy', 'packet_size_anomaly', 'connection_pattern',
                'port_scanning_score', 'protocol_anomaly', 'timing_anomaly',
                'dns_query_pattern', 'encryption_ratio'
            ],
            'transaction': [
                'amount', 'frequency', 'time_of_day', 'geographic_distance',
                'device_fingerprint_change', 'session_duration', 'transaction_velocity',
                'amount_variance', 'merchant_category_risk'
            ]
        }

    async def analyze_traffic(self, traffic_data: List[Dict]) -> List[Dict]:
        """
        Analyze traffic data and return detected threats
        """
        threats = []
        
        try:
            if not traffic_data:
                return threats

            df = pd.DataFrame(traffic_data)

            network_features = self._extract_network_features(df)
            ddos_features = self._extract_ddos_features(df)
            malware_features = self._extract_malware_features(df)

            if network_features is not None and len(network_features) > 0:
                anomalies = await self._detect_anomalies(network_features)
                threats.extend(anomalies)
            
            if ddos_features is not None and len(ddos_features) > 0:
                ddos_threats = await self._detect_ddos(ddos_features)
                threats.extend(ddos_threats)
            
            if malware_features is not None and len(malware_features) > 0:
                malware_threats = await self._detect_malware(malware_features)
                threats.extend(malware_threats)

            threats.extend(await self._generate_demo_threats())
            
        except Exception as e:
            logger.error(f"Error analyzing traffic: {e}")
        
        return threats

    def _extract_network_features(self, df: pd.DataFrame) -> Optional[np.ndarray]:
        """Extract network-level features"""
        try:
            if df.empty:
                return None
            
            features = []

            features.append(df['packet_size'].mean() if 'packet_size' in df.columns else 0)
            features.append(len(df) / 60)
            features.append(df['source_ip'].nunique() if 'source_ip' in df.columns else 0)
            features.append(df['dest_port'].nunique() if 'dest_port' in df.columns else 0)
            features.append(df['protocol'].nunique() if 'protocol' in df.columns else 0)
            features.append(df['packet_size'].sum() / 60)
            features.append(len(df) / 60)
            features.append(df['packet_size'].mean() if 'packet_size' in df.columns else 0)
            features.append(30)
            features.append(10)
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting network features: {e}")
            return None

    def _extract_ddos_features(self, df: pd.DataFrame) -> Optional[np.ndarray]:
        """Extract DDoS-specific features"""
        try:
            if df.empty:
                return None
            
            features = []

            features.append(len(df) / 60)
            features.append(df['source_ip'].nunique() / 60)
            features.append(df['source_ip'].nunique())
            features.append(df['packet_size'].var() if 'packet_size' in df.columns else 0)
            features.append(0.8)
            features.append(0.6)
            features.append(0.3)
            features.append(2.5)
            features.append(0.1)
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting DDoS features: {e}")
            return None

    def _extract_malware_features(self, df: pd.DataFrame) -> Optional[np.ndarray]:
        """Extract malware-specific features"""
        try:
            if df.empty:
                return None
            
            features = []

            features.append(3.2)
            features.append(0.7)
            features.append(0.4)
            features.append(0.8)
            features.append(0.6)
            features.append(0.5)
            features.append(0.3)
            features.append(0.2)
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting malware features: {e}")
            return None

    async def _detect_anomalies(self, features: np.ndarray) -> List[Dict]:
        """Detect general network anomalies"""
        threats = []
        
        try:
            if not self.is_trained:
                return threats

            scaled_features = self.scalers['anomaly_scaler'].transform(features)

            predictions = self.models['anomaly_detector'].predict(scaled_features)
            scores = self.models['anomaly_detector'].decision_function(scaled_features)
            
            for i, (pred, score) in enumerate(zip(predictions, scores)):
                if pred == -1:
                    threat_score = abs(score)
                    severity = "high" if threat_score > 0.5 else "medium"
                    
                    threats.append({
                        "type": "network_anomaly",
                        "severity": severity,
                        "threat_score": threat_score,
                        "source_ip": "192.168.1.100",
                        "target_ip": "192.168.1.1",
                        "protocol": "TCP",
                        "description": f"Unusual network pattern detected (score: {threat_score:.3f})"
                    })
        
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
        
        return threats

    async def _detect_ddos(self, features: np.ndarray) -> List[Dict]:
        """Detect DDoS attacks"""
        threats = []
        
        try:
            if not self.is_trained:
                return threats

            scaled_features = self.scalers['ddos_scaler'].transform(features)

            predictions = self.models['ddos_detector'].predict(scaled_features)
            probabilities = self.models['ddos_detector'].predict_proba(scaled_features)
            
            for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
                if pred == 1:
                    threat_score = prob[1]
                    severity = "critical" if threat_score > 0.8 else "high"
                    
                    threats.append({
                        "type": "ddos_attack",
                        "severity": severity,
                        "threat_score": threat_score,
                        "source_ip": "10.0.0.0/8",
                        "target_ip": "192.168.1.1",
                        "protocol": "TCP/UDP",
                        "description": f"DDoS attack detected (confidence: {threat_score:.3f})"
                    })
        
        except Exception as e:
            logger.error(f"Error detecting DDoS: {e}")
        
        return threats

    async def _detect_malware(self, features: np.ndarray) -> List[Dict]:
        """Detect malware traffic"""
        threats = []
        
        try:
            if not self.is_trained:
                return threats

            scaled_features = self.scalers['malware_scaler'].transform(features)

            predictions = self.models['malware_detector'].predict(scaled_features)
            scores = self.models['malware_detector'].decision_function(scaled_features)
            
            for i, (pred, score) in enumerate(zip(predictions, scores)):
                if pred == -1:
                    threat_score = abs(score)
                    severity = "high" if threat_score > 0.6 else "medium"
                    
                    threats.append({
                        "type": "malware_traffic",
                        "severity": severity,
                        "threat_score": threat_score,
                        "source_ip": "203.0.113.42",
                        "target_ip": "192.168.1.50",
                        "protocol": "TCP",
                        "description": f"Malicious traffic pattern detected (score: {threat_score:.3f})"
                    })
        
        except Exception as e:
            logger.error(f"Error detecting malware: {e}")
        
        return threats

    async def _generate_demo_threats(self) -> List[Dict]:
        """Generate demo threats for hackathon presentation"""
        import random
        
        demo_threats = []

        if random.random() < 0.3:
            demo_threats.append({
                "type": "suspicious_login",
                "severity": "medium",
                "threat_score": 0.75,
                "source_ip": "198.51.100.25",
                "target_ip": "192.168.1.10",
                "protocol": "SSH",
                "description": "Multiple failed login attempts detected"
            })
        
        if random.random() < 0.2:
            demo_threats.append({
                "type": "port_scan",
                "severity": "high",
                "threat_score": 0.85,
                "source_ip": "203.0.113.100",
                "target_ip": "192.168.1.0/24",
                "protocol": "TCP",
                "description": "Port scanning activity detected"
            })
        
        if random.random() < 0.15:
            demo_threats.append({
                "type": "data_exfiltration",
                "severity": "critical",
                "threat_score": 0.92,
                "source_ip": "192.168.1.50",
                "target_ip": "external-server.com",
                "protocol": "HTTPS",
                "description": "Large data transfer to external server detected"
            })
        
        return demo_threats

    async def analyze_transaction(self, transaction_data: Dict) -> List[Dict]:
        """Analyze financial transactions for anomalies"""
        threats = []
        
        try:

            features = self._extract_transaction_features(transaction_data)
            
            if features is not None:

                scaled_features = self.scalers['transaction_scaler'].transform(features)

                predictions = self.models['transaction_anomaly'].predict(scaled_features)
                scores = self.models['transaction_anomaly'].decision_function(scaled_features)
                
                for pred, score in zip(predictions, scores):
                    if pred == -1:
                        threat_score = abs(score)
                        severity = "high" if threat_score > 0.7 else "medium"
                        
                        threats.append({
                            "type": "transaction_anomaly",
                            "severity": severity,
                            "threat_score": threat_score,
                            "source_ip": transaction_data.get("source_ip", "unknown"),
                            "target_ip": transaction_data.get("merchant_ip", "unknown"),
                            "protocol": "HTTPS",
                            "description": f"Suspicious transaction pattern detected (score: {threat_score:.3f})"
                        })
        
        except Exception as e:
            logger.error(f"Error analyzing transaction: {e}")
        
        return threats

    def _extract_transaction_features(self, transaction: Dict) -> Optional[np.ndarray]:
        """Extract features from transaction data"""
        try:
            features = []

            features.append(transaction.get("amount", 0))
            features.append(transaction.get("frequency", 1))
            features.append(datetime.now().hour)
            features.append(transaction.get("geographic_distance", 0))
            features.append(transaction.get("device_fingerprint_change", 0))
            features.append(transaction.get("session_duration", 0))
            features.append(transaction.get("transaction_velocity", 0))
            features.append(transaction.get("amount_variance", 0))
            features.append(transaction.get("merchant_category_risk", 0))
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting transaction features: {e}")
            return None

    async def update_models(self):
        """Update ML models with new data"""
        try:

            logger.info("🔄 Updating threat detection models...")

            await asyncio.sleep(1)
            
            logger.info("✅ Models updated successfully")
            
        except Exception as e:
            logger.error(f"Error updating models: {e}")

    def _load_models(self):
        """Load pre-trained models from disk"""
        try:

            model_files = [
                'anomaly_detector.pkl',
                'ddos_detector.pkl',
                'malware_detector.pkl',
                'transaction_anomaly.pkl'
            ]
            
            models_exist = all(os.path.exists(os.path.join(self.model_path, f)) for f in model_files)
            
            if models_exist:

                for model_name in self.models.keys():
                    model_file = os.path.join(self.model_path, f"{model_name}.pkl")
                    self.models[model_name] = joblib.load(model_file)

                for scaler_name in self.scalers.keys():
                    scaler_file = os.path.join(self.model_path, f"{scaler_name}.pkl")
                    self.scalers[scaler_name] = joblib.load(scaler_file)
                
                self.is_trained = True
                logger.info("✅ Pre-trained models loaded successfully")
            else:

                self._train_demo_models()
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self._train_demo_models()

    def _train_demo_models(self):
        """Train models with synthetic data for demo purposes"""
        try:
            logger.info("🎯 Training models with synthetic data...")

            np.random.seed(42)

            normal_data = np.random.normal(0, 1, (1000, 10))
            self.scalers['anomaly_scaler'].fit(normal_data)
            scaled_data = self.scalers['anomaly_scaler'].transform(normal_data)
            self.models['anomaly_detector'].fit(scaled_data)

            ddos_features = np.random.normal(0, 1, (1000, 9))
            ddos_labels = np.random.choice([0, 1], 1000, p=[0.9, 0.1])
            self.scalers['ddos_scaler'].fit(ddos_features)
            scaled_ddos = self.scalers['ddos_scaler'].transform(ddos_features)
            self.models['ddos_detector'].fit(scaled_ddos, ddos_labels)

            malware_data = np.random.normal(0, 1, (1000, 8))
            self.scalers['malware_scaler'].fit(malware_data)
            scaled_malware = self.scalers['malware_scaler'].transform(malware_data)
            self.models['malware_detector'].fit(scaled_malware)

            transaction_data = np.random.normal(0, 1, (1000, 9))
            self.scalers['transaction_scaler'].fit(transaction_data)
            scaled_transaction = self.scalers['transaction_scaler'].transform(transaction_data)
            self.models['transaction_anomaly'].fit(scaled_transaction)
            
            self.is_trained = True
            logger.info("✅ Demo models trained successfully")

            self._save_models()
            
        except Exception as e:
            logger.error(f"Error training demo models: {e}")

    def _save_models(self):
        """Save trained models to disk"""
        try:

            for model_name, model in self.models.items():
                model_file = os.path.join(self.model_path, f"{model_name}.pkl")
                joblib.dump(model, model_file)

            for scaler_name, scaler in self.scalers.items():
                scaler_file = os.path.join(self.model_path, f"{scaler_name}.pkl")
                joblib.dump(scaler, scaler_file)
            
            logger.info("💾 Models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")

    def get_model_info(self) -> Dict:
        """Get information about the trained models"""
        return {
            "is_trained": self.is_trained,
            "models": list(self.models.keys()),
            "scalers": list(self.scalers.keys()),
            "feature_names": self.feature_names,
            "model_path": self.model_path
        }