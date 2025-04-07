import asyncio
import time
import re

class LogsAnalyzer:
    def __init__(self):
        # Patterns to look for in logs
        self.suspicious_patterns = [
            (r"Failed password for .* from", "Authentication Failure"),
            (r"Authentication failure", "Authentication Failure"),
            (r"POSSIBLE BREAK-IN ATTEMPT", "Break-in Attempt"),
            (r"Invalid user", "Invalid User Access"),
            (r"error: maximum authentication attempts exceeded", "Brute Force Attempt"),
            (r"refused connect from", "Connection Refused"),
            (r"segfault at", "Application Crash"),
            (r"denied.*SELinux", "SELinux Denial"),
            (r"firewall.*DROP", "Firewall Drop"),
            (r"sudo:.*COMMAND=", "Privileged Command Execution")
        ]
        
        # Track authentication failures by IP
        self.auth_failures = {}  # {ip: [(timestamp, username), ...]}
        
    async def analyze(self, logs_data):
        """Analyze logs for suspicious patterns"""
        if not logs_data:
            return []
            
        alerts = []
        current_time = time.time()
        
        for log in logs_data:
            log_content = log.get('content', '')
            log_source = log.get('source', 'unknown')
            
            # Check for suspicious patterns
            for pattern, alert_type in self.suspicious_patterns:
                if re.search(pattern, log_content, re.IGNORECASE):
                    # Extract IP address if present
                    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_content)
                    ip = ip_match.group(0) if ip_match else "unknown"
                    
                    # Track authentication failures
                    if alert_type == "Authentication Failure":
                        self._track_auth_failure(ip, log_content, current_time)
                    
                    # Create alert
                    alerts.append({
                        'timestamp': current_time,
                        'type': alert_type,
                        'severity': 'medium',
                        'source': f'system_logs:{log_source}',
                        'description': f"{alert_type} detected: {log_content[:100]}..."
                    })
                    
                    break  # Stop after first match
                    
        # Check for brute force attempts
        brute_force_alerts = self._detect_brute_force(current_time)
        alerts.extend(brute_force_alerts)
        
        # Clean up old entries
        self._cleanup_old_entries(current_time - 300)  # Remove entries older than 5 minutes
        
        return alerts
        
    def _track_auth_failure(self, ip, log_content, timestamp):
        """Track authentication failures by IP"""
        if ip == "unknown":
            return
            
        # Extract username if possible
        username_match = re.search(r"user (\w+)", log_content)
        username = username_match.group(1) if username_match else "unknown"
        
        if ip not in self.auth_failures:
            self.auth_failures[ip] = []
            
        self.auth_failures[ip].append((timestamp, username))
        
    def _detect_brute_force(self, current_time):
        """Detect brute force attempts based on auth failures"""
        alerts = []
        
        for ip, failures in self.auth_failures.items():
            # Filter recent failures (last 2 minutes)
            recent_failures = [f for f in failures if f[0] > current_time - 120]
            
            # Check for many failures
            if len(recent_failures) >= 5:
                # Check if multiple usernames were targeted
                usernames = set(f[1] for f in recent_failures)
                
                if len(usernames) >= 3:
                    alert_type = "User Enumeration Attempt"
                    severity = "high"
                    description = f"IP {ip} attempted to authenticate as {len(usernames)} different users"
                else:
                    alert_type = "Brute Force Attempt"
                    severity = "high"
                    description = f"IP {ip} had {len(recent_failures)} authentication failures in 2 minutes"
                    
                alerts.append({
                    'timestamp': current_time,
                    'type': alert_type,
                    'severity': severity,
                    'source': 'system_logs:auth',
                    'description': description
                })
                
        return alerts
        
    def _cleanup_old_entries(self, cutoff_time):
        """Remove old entries from tracking dictionaries"""
        for ip in list(self.auth_failures.keys()):
            self.auth_failures[ip] = [f for f in self.auth_failures[ip] if f[0] > cutoff_time]
            if not self.auth_failures[ip]:
                del self.auth_failures[ip]
