import asyncio
from .metrics_analyzer import MetricsAnalyzer
from .network_analyzer import NetworkAnalyzer
from .logs_analyzer import LogsAnalyzer
from .ml_network_analyzer import MLNetworkAnalyzer  # Import the new ML analyzer

class AnalyzerEngine:
    def __init__(self, data_collector):
        print("Initializing AnalyzerEngine...")
        self.data_collector = data_collector
        
        # Initialize analyzers
        self.metrics_analyzer = MetricsAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.logs_analyzer = LogsAnalyzer()
        self.ml_network_analyzer = MLNetworkAnalyzer()  # Add the ML analyzer
        
        # Alert buffer
        self.alerts = []
        self._lock = asyncio.Lock()
        self.active = True
        print("AnalyzerEngine initialized")
        
    async def start_analysis(self):
        """Start continuous analysis of collected data"""
        while self.active:
            try:
                # Get current data
                data = await self.data_collector.get_collected_data()
                
                # Analyze each data type
                analysis_tasks = [
                    self._analyze_metrics(data['metrics']),
                    self._analyze_network(data['network']),
                    self._analyze_logs(data['logs']),
                    self._analyze_ml_network(data['network'])  # Add ML network analysis
                ]
                
                await asyncio.gather(*analysis_tasks)
                
                # Short delay before next analysis cycle
                await asyncio.sleep(1)
                
            except Exception as e:
                print(f"Error in analysis cycle: {str(e)}")
                await asyncio.sleep(5)  # Longer delay on error
                
    async def _analyze_metrics(self, metrics_data):
        """Analyze system metrics"""
        if not metrics_data:
            return
            
        alerts = await self.metrics_analyzer.analyze(metrics_data)
        if alerts:
            await self._add_alerts(alerts)
            
    async def _analyze_network(self, network_data):
        """Analyze network traffic"""
        if not network_data:
            return
            
        alerts = await self.network_analyzer.analyze(network_data)
        if alerts:
            await self._add_alerts(alerts)
    
    async def _analyze_ml_network(self, network_data):
        """Analyze network traffic using ML models"""
        if not network_data:
            return
            
        alerts = await self.ml_network_analyzer.analyze(network_data)
        if alerts:
            await self._add_alerts(alerts)
            
    async def _analyze_logs(self, logs_data):
        """Analyze system logs"""
        if not logs_data:
            return
            
        alerts = await self.logs_analyzer.analyze(logs_data)
        if alerts:
            await self._add_alerts(alerts)
            
    async def _add_alerts(self, new_alerts):
        """Add alerts to buffer with lock protection"""
        if not new_alerts:
            return
            
        async with self._lock:
            self.alerts.extend(new_alerts)
            
        # Process alerts
        for alert in new_alerts:
            await self._process_alert(alert)
            
    async def _process_alert(self, alert):
        """Process a single alert"""
        from alerts.alert_handler import AlertHandler
        
        # Create alert handler
        handler = AlertHandler()
        
        # Send alert notification
        await handler.send_alert(alert)
        
        # Log alert to file
        await handler.log_alert(alert)
        
        # Print alert to console
        severity = alert.get('severity', 'unknown').upper()
        print(f"[{severity} ALERT] {alert.get('type')}: {alert.get('description')}")
        
    async def get_alerts(self):
        """Get current alerts with lock protection"""
        async with self._lock:
            return self.alerts.copy()
            
    async def cleanup(self):
        """Cleanup resources"""
        print("Starting analyzer cleanup...")
        self.active = False
        print("Analyzer cleanup completed")