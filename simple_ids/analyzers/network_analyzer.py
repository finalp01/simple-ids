import asyncio
import time
import ipaddress

class NetworkAnalyzer:
    def __init__(self):
        # Port scan detection thresholds
        self.port_scan_threshold = 10  # Number of different ports in short time
        self.port_scan_window = 5  # Time window in seconds
        
        # Track IPs and their accessed ports
        self.ip_port_access = {}  # {ip: [(timestamp, port), ...]}
        
        # Deauthentication attack detection
        self.deauth_threshold = 5  # Number of deauth packets in window
        self.deauth_window = 3  # Time window in seconds
        self.deauth_frames = {}  # {mac_address: [(timestamp), ...]}
        
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
            frame_type = packet.get('frame_type', '')
            frame_subtype = packet.get('frame_subtype', '')
            src_mac = packet.get('src_mac', '')
            
            # Track source IP port access
            if src_ip:
                if src_ip not in self.ip_port_access:
                    self.ip_port_access[src_ip] = []
                self.ip_port_access[src_ip].append((current_time, dst_port))
            
            # Check for deauthentication frames (WiFi)
            if frame_type == 'management' and frame_subtype == 'deauth' and src_mac:
                if src_mac not in self.deauth_frames:
                    self.deauth_frames[src_mac] = []
                self.deauth_frames[src_mac].append(current_time)
                
            # Check for common attack ports
            suspicious_ports = {22: 'SSH', 3389: 'RDP', 445: 'SMB'}
            if dst_port in suspicious_ports and src_ip and not self._is_internal_ip(src_ip):
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
        
        # Check for deauthentication attacks
        deauth_alerts = self._detect_deauth_attacks(current_time)
        alerts.extend(deauth_alerts)
        
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
    
    def _detect_deauth_attacks(self, current_time):
        """Detect potential deauthentication attacks"""
        alerts = []
        
        for mac, timestamps in self.deauth_frames.items():
            # Filter deauth frames within window
            recent_frames = [t for t in timestamps if t > current_time - self.deauth_window]
            
            if len(recent_frames) >= self.deauth_threshold:
                alerts.append({
                    'timestamp': current_time,
                    'type': 'WiFi Deauthentication Attack',
                    'severity': 'high',
                    'source': 'network_traffic',
                    'description': f"Possible deauthentication attack detected from MAC {mac}: {len(recent_frames)} deauth frames in {self.deauth_window} seconds"
                })
                
        return alerts
        
    def _cleanup_old_entries(self, cutoff_time):
        """Remove old entries from tracking dictionaries"""
        # Clean up port access tracking
        for ip in list(self.ip_port_access.keys()):
            self.ip_port_access[ip] = [a for a in self.ip_port_access[ip] if a[0] > cutoff_time]
            if not self.ip_port_access[ip]:
                del self.ip_port_access[ip]
        
        # Clean up deauth frame tracking
        for mac in list(self.deauth_frames.keys()):
            self.deauth_frames[mac] = [t for t in self.deauth_frames[mac] if t > cutoff_time]
            if not self.deauth_frames[mac]:
                del self.deauth_frames[mac]
                
    def _is_internal_ip(self, ip):
        """Check if IP is in private ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False