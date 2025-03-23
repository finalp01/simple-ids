import asyncio
import random
import time
from scapy.all import sniff, IP

class NetworkTrafficCollector:
    def __init__(self):
        self.active = True
        self.packet_buffer = []
        self._capture_task = None
        
    def start_capture(self):
        """Start packet capture in background"""
        if self._capture_task is None:
            self._capture_task = asyncio.create_task(self._capture_packets())
            
    async def _capture_packets(self):
        """Background task to capture packets"""
        try:
            while self.active:
                # In a real implementation, this would use scapy or similar
                # For demo, we'll generate mock data
                await asyncio.sleep(0.05)
                if random.random() > 0.7:  # Simulate packet capture rate
                    self.packet_buffer.append(self._create_mock_packet())
        except Exception as e:
            print(f"Error in packet capture: {str(e)}")
            
    def _create_mock_packet(self):
        """Create mock packet data for demonstration"""
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"
        return {
            'timestamp': time.time(),
            'src': src_ip,
            'dst': dst_ip,
            'proto': random.choice(['TCP', 'UDP', 'ICMP']),
            'size': random.randint(64, 1500),
            'flags': random.choice(['', 'S', 'SA', 'A', 'FA', 'R']),
            'sport': random.randint(1024, 65535),
            'dport': random.choice([80, 443, 22, 53, 3389, random.randint(1024, 65535)])
        }
        
    async def get_packets(self):
        """Get and clear packet buffer"""
        if not self.active:
            return []
            
        # Start capture if not already running
        self.start_capture()
        
        # Take current packets and clear buffer
        packets = self.packet_buffer.copy()
        self.packet_buffer.clear()
        return packets
        
    async def cleanup(self):
        """Cleanup resources"""
        self.active = False
        if self._capture_task:
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass
            self._capture_task = None
