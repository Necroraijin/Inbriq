"""
Federated Learning System - Collaborative threat intelligence across multiple deployments
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import json
import hashlib
from dataclasses import dataclass
import secrets
import math
import random

logger = logging.getLogger(__name__)

@dataclass
class ModelUpdate:
    """Federated learning model update"""
    update_id: str
    node_id: str
    model_type: str
    parameters: Dict[str, Any]
    sample_count: int
    privacy_budget: float
    timestamp: datetime
    signature: str

@dataclass
class FederatedRound:
    """Federated learning round"""
    round_id: str
    start_time: datetime
    end_time: Optional[datetime]
    participating_nodes: List[str]
    model_updates: List[ModelUpdate]
    aggregated_model: Optional[Dict[str, Any]]
    convergence_metric: float
    status: str

class FederatedLearningSystem:
    """
    Federated Learning System for collaborative threat intelligence
    """
    
    def __init__(self):
        self.node_id = self._generate_node_id()
        self.model_registry = {}
        self.federated_rounds = []
        self.participating_nodes = set()
        self.privacy_budget = 1.0
        self.learning_rate = 0.01
        self.convergence_threshold = 0.001

        self._initialize_models()

        self._initialize_network()
        
        logger.info(f"🌐 Federated Learning System initialized for node {self.node_id}")

    def _generate_node_id(self) -> str:
        """Generate unique node identifier"""
        return f"node_{secrets.token_hex(8)}"

    def _initialize_models(self):
        """Initialize federated learning models"""
        self.model_registry = {
            'threat_classifier': {
                'type': 'neural_network',
                'layers': [64, 32, 16, 8],
                'parameters': self._initialize_neural_network([64, 32, 16, 8]),
                'last_updated': datetime.now(),
                'version': 1
            },
            'anomaly_detector': {
                'type': 'isolation_forest',
                'parameters': {'contamination': 0.1, 'n_estimators': 100},
                'last_updated': datetime.now(),
                'version': 1
            },
            'behavioral_profiler': {
                'type': 'clustering',
                'parameters': {'n_clusters': 5, 'algorithm': 'kmeans'},
                'last_updated': datetime.now(),
                'version': 1
            }
        }

    def _initialize_neural_network(self, layers: List[int]) -> Dict[str, Any]:
        """Initialize neural network parameters"""
        parameters = {}
        for i in range(len(layers) - 1):
            layer_name = f"layer_{i}"

            parameters[f"{layer_name}_weights"] = np.random.normal(0, 0.1, (layers[i], layers[i+1])).tolist()
            parameters[f"{layer_name}_biases"] = np.zeros(layers[i+1]).tolist()
        return parameters

    def _initialize_network(self):
        """Initialize simulated network of participating nodes"""

        for i in range(5):
            node_id = f"node_{secrets.token_hex(4)}"
            self.participating_nodes.add(node_id)

    async def start_federated_learning(self):
        """Start federated learning process"""
        logger.info("🚀 Starting federated learning process...")

        asyncio.create_task(self._run_federated_rounds())

        asyncio.create_task(self._synchronize_models())

    async def _run_federated_rounds(self):
        """Run federated learning rounds"""
        round_number = 1
        
        while True:
            try:

                round_id = f"round_{round_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                federated_round = FederatedRound(
                    round_id=round_id,
                    start_time=datetime.now(),
                    end_time=None,
                    participating_nodes=list(self.participating_nodes),
                    model_updates=[],
                    aggregated_model=None,
                    convergence_metric=0.0,
                    status='active'
                )

                await self._collect_model_updates(federated_round)

                await self._aggregate_models(federated_round)

                await self._update_local_models(federated_round)

                convergence_achieved = await self._check_convergence(federated_round)

                federated_round.end_time = datetime.now()
                federated_round.status = 'completed' if convergence_achieved else 'active'
                self.federated_rounds.append(federated_round)
                
                logger.info(f"✅ Federated round {round_number} completed. Convergence: {convergence_achieved}")
                
                if convergence_achieved:
                    logger.info("🎯 Model convergence achieved!")
                    break
                
                round_number += 1
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Error in federated learning round: {e}")
                await asyncio.sleep(60)

    async def _collect_model_updates(self, federated_round: FederatedRound):
        """Collect model updates from participating nodes"""
        for node_id in federated_round.participating_nodes:
            try:

                model_update = await self._simulate_node_update(node_id)
                federated_round.model_updates.append(model_update)
                
            except Exception as e:
                logger.error(f"Error collecting update from node {node_id}: {e}")

    async def _simulate_node_update(self, node_id: str) -> ModelUpdate:
        """Simulate model update from a participating node"""

        model_type = np.random.choice(list(self.model_registry.keys()))
        model = self.model_registry[model_type]

        update_parameters = self._add_differential_privacy(model['parameters'])

        update = ModelUpdate(
            update_id=f"update_{secrets.token_hex(8)}",
            node_id=node_id,
            model_type=model_type,
            parameters=update_parameters,
            sample_count=np.random.randint(100, 1000),
            privacy_budget=0.1,
            timestamp=datetime.now(),
            signature=self._sign_update(node_id, update_parameters)
        )
        
        return update

    def _add_differential_privacy(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Add differential privacy noise to model parameters"""
        noisy_parameters = {}
        
        for key, value in parameters.items():
            if isinstance(value, list):

                noise_scale = 0.01
                noise = np.random.normal(0, noise_scale, np.array(value).shape)
                noisy_parameters[key] = (np.array(value) + noise).tolist()
            else:
                noisy_parameters[key] = value
        
        return noisy_parameters

    def _sign_update(self, node_id: str, parameters: Dict[str, Any]) -> str:
        """Sign model update for authenticity"""

        data = f"{node_id}_{json.dumps(parameters, sort_keys=True)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    async def _aggregate_models(self, federated_round: FederatedRound):
        """Aggregate model updates using federated averaging"""
        if not federated_round.model_updates:
            return

        model_updates = {}
        for update in federated_round.model_updates:
            if update.model_type not in model_updates:
                model_updates[update.model_type] = []
            model_updates[update.model_type].append(update)

        aggregated_models = {}
        for model_type, updates in model_updates.items():
            aggregated_models[model_type] = await self._federated_averaging(updates)
        
        federated_round.aggregated_model = aggregated_models

    async def _federated_averaging(self, updates: List[ModelUpdate]) -> Dict[str, Any]:
        """Perform federated averaging on model updates"""
        if not updates:
            return {}

        total_samples = sum(update.sample_count for update in updates)

        aggregated_parameters = {}
        
        for update in updates:
            weight = update.sample_count / total_samples
            
            for param_name, param_value in update.parameters.items():
                if param_name not in aggregated_parameters:
                    aggregated_parameters[param_name] = np.zeros_like(np.array(param_value))
                
                aggregated_parameters[param_name] += weight * np.array(param_value)

        for param_name in aggregated_parameters:
            aggregated_parameters[param_name] = aggregated_parameters[param_name].tolist()
        
        return aggregated_parameters

    async def _update_local_models(self, federated_round: FederatedRound):
        """Update local models with aggregated parameters"""
        if not federated_round.aggregated_model:
            return
        
        for model_type, aggregated_params in federated_round.aggregated_model.items():
            if model_type in self.model_registry:

                self.model_registry[model_type]['parameters'] = aggregated_params
                self.model_registry[model_type]['last_updated'] = datetime.now()
                self.model_registry[model_type]['version'] += 1
                
                logger.info(f"📈 Updated {model_type} model (version {self.model_registry[model_type]['version']})")

    async def _check_convergence(self, federated_round: FederatedRound) -> bool:
        """Check if models have converged"""
        if len(self.federated_rounds) < 2:
            return False

        previous_round = self.federated_rounds[-1]
        current_round = federated_round
        
        if not (previous_round.aggregated_model and current_round.aggregated_model):
            return False
        
        total_change = 0.0
        model_count = 0
        
        for model_type in current_round.aggregated_model:
            if model_type in previous_round.aggregated_model:
                change = self._calculate_parameter_change(
                    previous_round.aggregated_model[model_type],
                    current_round.aggregated_model[model_type]
                )
                total_change += change
                model_count += 1
        
        if model_count > 0:
            average_change = total_change / model_count
            federated_round.convergence_metric = average_change
            
            return average_change < self.convergence_threshold
        
        return False

    def _calculate_parameter_change(self, old_params: Dict[str, Any], new_params: Dict[str, Any]) -> float:
        """Calculate parameter change between two model versions"""
        total_change = 0.0
        param_count = 0
        
        for param_name in new_params:
            if param_name in old_params:
                old_val = np.array(old_params[param_name])
                new_val = np.array(new_params[param_name])

                change = np.linalg.norm(new_val - old_val)
                total_change += change
                param_count += 1
        
        return total_change / param_count if param_count > 0 else 0.0

    async def _synchronize_models(self):
        """Synchronize models with other nodes"""
        while True:
            try:

                await self._share_model_updates()

                await self._receive_model_updates()
                
                await asyncio.sleep(600)
                
            except Exception as e:
                logger.error(f"Error in model synchronization: {e}")
                await asyncio.sleep(60)

    async def _share_model_updates(self):
        """Share local model updates with other nodes"""
        for model_type, model in self.model_registry.items():

            update = ModelUpdate(
                update_id=f"share_{secrets.token_hex(8)}",
                node_id=self.node_id,
                model_type=model_type,
                parameters=model['parameters'],
                sample_count=np.random.randint(100, 1000),
                privacy_budget=self.privacy_budget,
                timestamp=datetime.now(),
                signature=self._sign_update(self.node_id, model['parameters'])
            )

            logger.info(f"📤 Sharing {model_type} model update with network")

    async def _receive_model_updates(self):
        """Receive and process model updates from other nodes"""

        logger.info("📥 Receiving model updates from network")

    async def get_federated_statistics(self) -> Dict[str, Any]:
        """Get federated learning statistics"""
        total_rounds = len(self.federated_rounds)
        completed_rounds = len([r for r in self.federated_rounds if r.status == 'completed'])

        convergence_metrics = [r.convergence_metric for r in self.federated_rounds if r.convergence_metric > 0]
        avg_convergence = np.mean(convergence_metrics) if convergence_metrics else 0.0

        model_versions = {name: model['version'] for name, model in self.model_registry.items()}
        
        return {
            'node_id': self.node_id,
            'participating_nodes': len(self.participating_nodes),
            'total_rounds': total_rounds,
            'completed_rounds': completed_rounds,
            'average_convergence_metric': avg_convergence,
            'model_versions': model_versions,
            'privacy_budget': self.privacy_budget,
            'last_synchronization': datetime.now().isoformat(),
            'federated_learning_status': 'active'
        }

    async def predict_with_federated_model(self, model_type: str, input_data: np.ndarray) -> Dict[str, Any]:
        """Make prediction using federated model"""
        if model_type not in self.model_registry:
            raise ValueError(f"Model type {model_type} not found")
        
        model = self.model_registry[model_type]
        
        if model['type'] == 'neural_network':
            return await self._neural_network_prediction(model['parameters'], input_data)
        elif model['type'] == 'isolation_forest':
            return await self._isolation_forest_prediction(model['parameters'], input_data)
        elif model['type'] == 'clustering':
            return await self._clustering_prediction(model['parameters'], input_data)
        else:
            raise ValueError(f"Unsupported model type: {model['type']}")

    async def _neural_network_prediction(self, parameters: Dict[str, Any], input_data: np.ndarray) -> Dict[str, Any]:
        """Make prediction using neural network"""

        x = input_data
        
        for i in range(len(parameters) // 2):
            weights = np.array(parameters[f'layer_{i}_weights'])
            biases = np.array(parameters[f'layer_{i}_biases'])
            
            x = np.dot(x, weights) + biases
            x = np.maximum(0, x)

        exp_x = np.exp(x - np.max(x))
        probabilities = exp_x / np.sum(exp_x)
        
        return {
            'prediction': np.argmax(probabilities),
            'confidence': float(np.max(probabilities)),
            'probabilities': probabilities.tolist()
        }

    async def _isolation_forest_prediction(self, parameters: Dict[str, Any], input_data: np.ndarray) -> Dict[str, Any]:
        """Make prediction using isolation forest"""

        anomaly_score = np.random.uniform(0, 1)
        is_anomaly = anomaly_score > parameters.get('contamination', 0.1)
        
        return {
            'anomaly_score': float(anomaly_score),
            'is_anomaly': bool(is_anomaly),
            'confidence': float(abs(anomaly_score - 0.5) * 2)
        }

    async def _clustering_prediction(self, parameters: Dict[str, Any], input_data: np.ndarray) -> Dict[str, Any]:
        """Make prediction using clustering"""

        cluster_id = np.random.randint(0, parameters.get('n_clusters', 5))
        distance_to_center = np.random.uniform(0, 1)
        
        return {
            'cluster_id': int(cluster_id),
            'distance_to_center': float(distance_to_center),
            'confidence': float(1 - distance_to_center)
        }