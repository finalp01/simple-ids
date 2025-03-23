import asyncio
import time
import ipaddress

class NetworkAnalyzer:
    def __init__(self):
        # Initialize IP reputation database (mock)
        self.suspicious_ips = set([
            "10.0.0.99",
            "192.168.1.200"
        ])
        
        # Port scan detection thresholds
        self.port_scan_threshold = 10  # Number of different ports in short time
        self.port_scan_window = 5  # Time window in seconds
        
        # Track IPs and their accessed ports
        self.ip_port_access = {}  # {ip: [(timestamp, port), ...]}
        
    async def analyze(self, network_data):
        """Analyze network traffic for suspicious patterns"""
        if not network_data:
            return []
            
        alerts = []
        current_time = time.time()
        
        # Update port access tracking
        for packet in network_data:
            src_ip = packet.get('src', '')
            dst_ip = packet.get('dst', '')
            dst_port = packet.get('dport', 0)
            
            # Track source IP port access
            if src_ip not in self.ip_port_access:
                self.ip_port_access[src_ip] = []
            self.ip_port_access[src_ip].append((current_time, dst_port))
            
            # Check for suspicious IPs
            if src_ip in self.suspicious_ips:
                alerts.append({
                    'timestamp': current_time,
                    'type': 'Suspicious IP Detected',
                    'severity': 'high',
                    'source': 'network_traffic',
                    'description': f"Connection from known suspicious IP: {src_ip}"
                })
                
            # Check for common attack ports
            suspicious_ports = {22: 'SSH', 3389: 'RDP', 445: 'SMB'}
            if dst_port in suspicious_ports and not self._is_internal_ip(src_ip):
                alerts.append({
                    'timestamp': current_time,
                    'type': f'{suspicious_ports[dst_port]} Access Attempt',
                    'severity': 'medium',
                    'source': 'network_traffic',
                    'description': f"External IP {src_ip} attempting to connect to {suspicious_ports[dst_port]} port {dst_port}"
                })
                
        # Check for port scanning
        port_scan_alerts = self._detect_port_scans(current_time)
        alerts.extend(port_scan_alerts)
        
        # Clean up old entries
        self._cleanup_old_entries(current_time - 60)  # Remove entries older than 60 seconds
        
        return alerts
        
    def _detect_port_scans(self, current_time):
        """Detect potential port scanning activity"""
        alerts = []
        
        for ip, accesses in self.ip_port_access.items():
            # Filter accesses within scan window
            recent_accesses = [a for a in accesses if a[0] > current_time - self.port_scan_window]
            
            # Count unique ports
            unique_ports = set(a[1] for a in recent_accesses)
            
            if len(unique_ports) >= self.port_scan_threshold:
                alerts.append({
                    'timestamp': current_time,
                    'type': 'Potential Port Scan',
                    'severity': 'high',
                    'source': 'network_traffic',
                    'description': f"IP {ip} accessed {len(unique_ports)} different ports in {self.port_scan_window} seconds"
                })
                
        return alerts
        
    def _cleanup_old_entries(self, cutoff_time):
        """Remove old entries from tracking dictionaries"""
        for ip in list(self.ip_port_access.keys()):
            self.ip_port_access[ip] = [a for a in self.ip_port_access[ip] if a[0] > cutoff_time]
            if not self.ip_port_access[ip]:
                del self.ip_port_access[ip]
                
    def _is_internal_ip(self, ip):
        """Check if IP is in private ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

