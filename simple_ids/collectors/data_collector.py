import asyncio
from collections import deque
from .system_metrics import SystemMetricsCollector
from .network_traffic import NetworkTrafficCollector
from .system_logs import SystemLogsCollector

class DataCollector:
    def __init__(self):
        print("Initializing DataCollector...")
        self.metrics_collector = SystemMetricsCollector()
        self.traffic_collector = NetworkTrafficCollector()
        self.logs_collector = SystemLogsCollector()
        self.data_buffer = {
            'metrics': deque(maxlen=100),
            'network': deque(maxlen=10000),
            'logs': deque(maxlen=1000)
        }
        self.active = True
        self._lock = asyncio.Lock()
        print("DataCollector initialized")
        
    async def collect_all_data(self):
        """Collect all data sources concurrently"""
        try:
            collection_tasks = [
                self._collect_metrics(),
                self._collect_network(),
                self._collect_logs()
            ]
            await asyncio.gather(*collection_tasks)
        except Exception as e:
            print(f"Error in collect_all_data: {str(e)}")
            raise
            
    async def _collect_metrics(self):
        """Continuous metrics collection"""
        while self.active:
            try:
                metrics = await self.metrics_collector.collect_metrics()
                if metrics:
                    async with self._lock:
                        self.data_buffer['metrics'].append(metrics)
            except Exception as e:
                print(f"Error collecting metrics: {str(e)}")
            await asyncio.sleep(1)
            
    async def _collect_network(self):
        """Continuous network collection"""
        while self.active:
            try:
                packets = await self.traffic_collector.get_packets()
                if packets:
                    async with self._lock:
                        self.data_buffer['network'].extend(packets)
            except Exception as e:
                print(f"Error collecting network data: {str(e)}")
            await asyncio.sleep(0.1)
            
    async def _collect_logs(self):
        """Continuous log collection"""
        try:
            async for log in self.logs_collector.collect_logs():
                if self.active:
                    async with self._lock:
                        self.data_buffer['logs'].append(log)
        except Exception as e:
            print(f"Error collecting logs: {str(e)}")
            
    async def get_collected_data(self):
        """Get current data snapshot with lock protection"""
        async with self._lock:
            return {
                'metrics': list(self.data_buffer['metrics']),
                'network': list(self.data_buffer['network']),
                'logs': list(self.data_buffer['logs'])
            }
            
    async def cleanup(self):
        """Cleanup all collectors"""
        print("Starting collector cleanup...")
        self.active = False
        try:
            await asyncio.gather(
                self.metrics_collector.cleanup(),
                self.traffic_collector.cleanup(),
                self.logs_collector.cleanup()
            )
            print("Collector cleanup completed")
        except Exception as e:
            print(f"Error during collector cleanup: {str(e)}")
