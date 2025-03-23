import asyncio
import time

class MetricsAnalyzer:
    def __init__(self):
        # Define thresholds
        self.cpu_threshold = 90  # CPU usage % threshold
        self.memory_threshold = 85  # Memory usage % threshold
        self.previous_metrics = None
        
    async def analyze(self, metrics_data):
        """Analyze system metrics for anomalies"""
        if not metrics_data:
            return []
            
        alerts = []
        latest_metrics = metrics_data[-1]
        
        # Check CPU usage
        if latest_metrics['cpu_percent'] > self.cpu_threshold:
            alerts.append({
                'timestamp': time.time(),
                'type': 'High CPU Usage',
                'severity': 'warning',
                'source': 'system_metrics',
                'description': f"CPU usage at {latest_metrics['cpu_percent']}% exceeds threshold of {self.cpu_threshold}%"
            })
            
        # Check memory usage
        if latest_metrics['memory_percent'] > self.memory_threshold:
            alerts.append({
                'timestamp': time.time(),
                'type': 'High Memory Usage',
                'severity': 'warning',
                'source': 'system_metrics',
                'description': f"Memory usage at {latest_metrics['memory_percent']}% exceeds threshold of {self.memory_threshold}%"
            })
            
        # Check for sudden increase in processes (if we have previous metrics)
        if self.previous_metrics and 'processes' in latest_metrics and 'processes' in self.previous_metrics:
            process_increase = latest_metrics['processes'] - self.previous_metrics['processes']
            if process_increase > 10:  # More than 10 new processes
                alerts.append({
                    'timestamp': time.time(),
                    'type': 'Process Spawn Spike',
                    'severity': 'medium',
                    'source': 'system_metrics',
                    'description': f"Sudden increase of {process_increase} processes detected"
                })
                
        # Check for sudden increase in network connections
        if self.previous_metrics and 'connections' in latest_metrics and 'connections' in self.previous_metrics:
            conn_increase = latest_metrics['connections'] - self.previous_metrics['connections']
            if conn_increase > 20:  # More than 20 new connections
                alerts.append({
                    'timestamp': time.time(),
                    'type': 'Connection Spike',
                    'severity': 'medium',
                    'source': 'system_metrics',
                    'description': f"Sudden increase of {conn_increase} network connections detected"
                })
                
        # Update previous metrics
        self.previous_metrics = latest_metrics
        
        return alerts
