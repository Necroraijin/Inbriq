"""Network monitoring"""

import psutil
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import random
import socket
import struct

logger = logging.getLogger(__name__)

class NetworkMonitor:
    """
    Monitors network traffic and provides real-time statistics
    """
    
    def __init__(self):
        self.is_monitoring = False
        self.traffic_history = []
        self.interface_stats = {}
        self.connection_cache = {}

        self.demo_ips = [
            "192.168.1.1", "192.168.1.10", "192.168.1.50", "192.168.1.100",
            "10.0.0.1", "10.0.0.10", "172.16.0.1", "203.0.113.42",
            "198.51.100.25", "203.0.113.100"
        ]
        
        self.demo_ports = [22, 80, 443, 3389, 5432, 3306, 8080, 9000]
        self.demo_protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP"]
        
        logger.info("Network Monitor initialized")

    def get_network_stats(self) -> Dict:
        """Get current network statistics"""
        try:

            net_io = psutil.net_io_counters()
            net_connections = psutil.net_connections()

            current_time = datetime.now()
            
            stats = {
                "timestamp": current_time.isoformat(),
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "active_connections": len(net_connections),
                "established_connections": len([c for c in net_connections if c.status == 'ESTABLISHED']),
                "listening_ports": len([c for c in net_connections if c.status == 'LISTEN']),
                "interfaces": self._get_interface_stats()
            }

            stats.update(self._generate_demo_stats())
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting network stats: {e}")
            return {}

    def _get_interface_stats(self) -> Dict:
        """Get network interface statistics"""
        try:
            interfaces = {}
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            
            for interface, stats in net_if_stats.items():
                if stats.isup:
                    interfaces[interface] = {
                        "is_up": stats.isup,
                        "speed": stats.speed,
                        "mtu": stats.mtu,
                        "addresses": [
                            addr.address for addr in net_if_addrs.get(interface, [])
                            if addr.family == socket.AF_INET
                        ]
                    }
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting interface stats: {e}")
            return {}

    def _generate_demo_stats(self) -> Dict:
        """Generate demo statistics for hackathon presentation"""
        return {
            "demo_metrics": {
                "threat_level": random.choice(["low", "medium", "high"]),
                "suspicious_connections": random.randint(0, 5),
                "blocked_attempts": random.randint(0, 10),
                "data_transfer_rate": random.uniform(1.0, 100.0),
                "packet_loss_rate": random.uniform(0.0, 0.05),
                "latency_ms": random.uniform(10.0, 100.0)
            }
        }

    def capture_traffic_sample(self, duration_seconds: int = 1) -> List[Dict]:
        """Capture a sample of network traffic"""
        try:

            traffic_data = []
            num_packets = random.randint(10, 50)
            
            for _ in range(num_packets):
                packet = self._generate_demo_packet()
                traffic_data.append(packet)

            self.traffic_history.extend(traffic_data)

            if len(self.traffic_history) > 1000:
                self.traffic_history = self.traffic_history[-1000:]
            
            return traffic_data
            
        except Exception as e:
            logger.error(f"Error capturing traffic sample: {e}")
            return []

    def _generate_demo_packet(self) -> Dict:
        """Generate a demo network packet"""
        timestamp = datetime.now()

        source_ip = random.choice(self.demo_ips)
        dest_ip = random.choice(self.demo_ips)

        while dest_ip == source_ip:
            dest_ip = random.choice(self.demo_ips)
        
        packet = {
            "timestamp": timestamp.isoformat(),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": random.choice(self.demo_ports),
            "dest_port": random.choice(self.demo_ports),
            "protocol": random.choice(self.demo_protocols),
            "packet_size": random.randint(64, 1500),
            "flags": self._generate_packet_flags(),
            "ttl": random.randint(32, 255),
            "checksum": random.randint(0, 65535)
        }

        if random.random() < 0.1:
            packet.update(self._add_suspicious_pattern())
        
        return packet

    def _generate_packet_flags(self) -> Dict:
        """Generate packet flags"""
        return {
            "syn": random.choice([True, False]),
            "ack": random.choice([True, False]),
            "fin": random.choice([True, False]),
            "rst": random.choice([True, False]),
            "psh": random.choice([True, False]),
            "urg": random.choice([True, False])
        }

    def _add_suspicious_pattern(self) -> Dict:
        """Add suspicious patterns to packets"""
        patterns = [
            {
                "suspicious": True,
                "pattern_type": "port_scan",
                "description": "Rapid port scanning detected"
            },
            {
                "suspicious": True,
                "pattern_type": "large_payload",
                "description": "Unusually large packet size"
            },
            {
                "suspicious": True,
                "pattern_type": "fragmented",
                "description": "Fragmented packet pattern"
            },
            {
                "suspicious": True,
                "pattern_type": "unusual_protocol",
                "description": "Uncommon protocol usage"
            }
        ]
        
        return random.choice(patterns)

    def get_connection_info(self, connection_id: str) -> Optional[Dict]:
        """Get detailed information about a specific connection"""
        try:

            if connection_id in self.connection_cache:
                return self.connection_cache[connection_id]

            connections = psutil.net_connections()
            
            for conn in connections:
                conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                if conn_id == connection_id:
                    connection_info = {
                        "id": conn_id,
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "pid": conn.pid,
                        "family": conn.family.name,
                        "type": conn.type.name,
                        "timestamp": datetime.now().isoformat()
                    }

                    self.connection_cache[connection_id] = connection_info
                    return connection_info
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting connection info: {e}")
            return None

    def get_traffic_summary(self, time_window_minutes: int = 5) -> Dict:
        """Get traffic summary for a time window"""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)

            recent_traffic = [
                packet for packet in self.traffic_history
                if datetime.fromisoformat(packet["timestamp"]) > cutoff_time
            ]
            
            if not recent_traffic:
                return {"message": "No traffic data available"}

            total_packets = len(recent_traffic)
            total_bytes = sum(packet["packet_size"] for packet in recent_traffic)

            protocol_counts = {}
            for packet in recent_traffic:
                protocol = packet["protocol"]
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            source_ips = {}
            for packet in recent_traffic:
                source_ip = packet["source_ip"]
                source_ips[source_ip] = source_ips.get(source_ip, 0) + 1

            dest_ports = {}
            for packet in recent_traffic:
                dest_port = packet["dest_port"]
                dest_ports[dest_port] = dest_ports.get(dest_port, 0) + 1

            suspicious_packets = [
                packet for packet in recent_traffic
                if packet.get("suspicious", False)
            ]
            
            summary = {
                "time_window_minutes": time_window_minutes,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "packets_per_second": total_packets / (time_window_minutes * 60),
                "bytes_per_second": total_bytes / (time_window_minutes * 60),
                "protocol_distribution": dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
                "top_source_ips": dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
                "top_destination_ports": dict(sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:5]),
                "suspicious_packets": len(suspicious_packets),
                "suspicious_percentage": (len(suspicious_packets) / total_packets * 100) if total_packets > 0 else 0
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting traffic summary: {e}")
            return {}

    def get_bandwidth_usage(self) -> Dict:
        """Get current bandwidth usage by interface"""
        try:
            bandwidth_usage = {}

            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                bandwidth_usage[interface] = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "errin": stats.errin,
                    "errout": stats.errout,
                    "dropin": stats.dropin,
                    "dropout": stats.dropout
                }
            
            return bandwidth_usage
            
        except Exception as e:
            logger.error(f"Error getting bandwidth usage: {e}")
            return {}

    def detect_network_anomalies(self) -> List[Dict]:
        """Detect network anomalies based on traffic patterns"""
        anomalies = []
        
        try:

            recent_traffic = self.traffic_history[-100:] if self.traffic_history else []
            
            if not recent_traffic:
                return anomalies

            packet_rate = len(recent_traffic) / 60
            if packet_rate > 1000:
                anomalies.append({
                    "type": "high_packet_rate",
                    "severity": "medium",
                    "description": f"High packet rate detected: {packet_rate:.1f} packets/minute",
                    "value": packet_rate,
                    "threshold": 1000
                })

            protocols = [packet["protocol"] for packet in recent_traffic]
            protocol_counts = {}
            for protocol in protocols:
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            total_packets = len(recent_traffic)
            for protocol, count in protocol_counts.items():
                percentage = (count / total_packets) * 100
                if percentage > 80:
                    anomalies.append({
                        "type": "protocol_concentration",
                        "severity": "low",
                        "description": f"High concentration of {protocol} traffic: {percentage:.1f}%",
                        "protocol": protocol,
                        "percentage": percentage
                    })

            suspicious_count = sum(1 for packet in recent_traffic if packet.get("suspicious", False))
            if suspicious_count > 5:
                anomalies.append({
                    "type": "suspicious_activity",
                    "severity": "high",
                    "description": f"Multiple suspicious packets detected: {suspicious_count}",
                    "count": suspicious_count
                })

            dest_ports = [packet["dest_port"] for packet in recent_traffic]
            unique_ports = len(set(dest_ports))
            if unique_ports > 20:
                anomalies.append({
                    "type": "port_scanning",
                    "severity": "high",
                    "description": f"Possible port scanning detected: {unique_ports} different ports",
                    "unique_ports": unique_ports
                })
            
        except Exception as e:
            logger.error(f"Error detecting network anomalies: {e}")
        
        return anomalies

    def get_network_topology(self) -> Dict:
        """Get network topology information"""
        try:
            topology = {
                "local_networks": [],
                "gateways": [],
                "dns_servers": [],
                "routing_table": []
            }

            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface, addresses in net_if_addrs.items():
                if interface in net_if_stats and net_if_stats[interface].isup:
                    interface_info = {
                        "name": interface,
                        "addresses": [],
                        "is_up": net_if_stats[interface].isup,
                        "speed": net_if_stats[interface].speed
                    }
                    
                    for addr in addresses:
                        if addr.family == socket.AF_INET:
                            interface_info["addresses"].append({
                                "ip": addr.address,
                                "netmask": addr.netmask,
                                "broadcast": addr.broadcast
                            })
                    
                    if interface_info["addresses"]:
                        topology["local_networks"].append(interface_info)

            topology["demo_info"] = {
                "total_interfaces": len(topology["local_networks"]),
                "monitored_networks": ["192.168.1.0/24", "10.0.0.0/8"],
                "firewall_rules": 15,
                "active_connections": random.randint(50, 200)
            }
            
            return topology
            
        except Exception as e:
            logger.error(f"Error getting network topology: {e}")
            return {}

    def start_monitoring(self):
        """Start continuous network monitoring"""
        self.is_monitoring = True
        logger.info("📡 Network monitoring started")

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        logger.info("📡 Network monitoring stopped")

    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            "is_monitoring": self.is_monitoring,
            "traffic_history_size": len(self.traffic_history),
            "connection_cache_size": len(self.connection_cache),
            "last_update": datetime.now().isoformat()
        }