import asyncio
import psutil
import time

class SystemMetricsCollector:
    def __init__(self):
        self.active = True
        
    async def collect_metrics(self):
        """Collect system metrics"""
        if not self.active:
            return None
            
        return {
            'timestamp': time.time(),
            'cpu_percent': psutil.cpu_percent(interval=None),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict() if hasattr(psutil, 'disk_io_counters') else {},
            'network_io': psutil.net_io_counters()._asdict(),
            'connections': len(psutil.net_connections()),
            'processes': len(psutil.pids()),
        }
        
    async def cleanup(self):
        """Cleanup resources"""
        self.active = False
        await asyncio.sleep(0)  # Yield to event loop
