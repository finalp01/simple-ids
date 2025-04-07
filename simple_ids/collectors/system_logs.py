import asyncio
import os
import time
import random

class SystemLogsCollector:
    def __init__(self):
        self.active = True
        self.log_paths = [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/secure"
        ]
        
    async def collect_logs(self):
        """Asynchronous log collection generator"""
        if not os.path.exists(self.log_paths[0]) and not os.path.exists(self.log_paths[1]) and not os.path.exists(self.log_paths[2]):
            # If log files don't exist (e.g., on Windows or non-standard Linux), use mock logs
            async for log in self._collect_mock_logs():
                yield log
        else:
            # Use real logs if available
            async for log in self._collect_real_logs():
                yield log
                
    async def _collect_real_logs(self):
        """Collect logs from real system files"""
        for log_path in self.log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r') as f:
                        # Seek to end of file
                        f.seek(0, 2)
                        
                        while self.active:
                            line = f.readline()
                            if line:
                                yield {
                                    'timestamp': time.time(),
                                    'source': log_path,
                                    'content': line.strip()
                                }
                            else:
                                await asyncio.sleep(0.5)
                except Exception as e:
                    print(f"Error reading log {log_path}: {str(e)}")
                    
    async def _collect_mock_logs(self):
        """Generate mock log entries for demonstration"""
        log_types = [
            "Authentication failure for user {user} from {ip}",
            "Successful login for user {user} from {ip}",
            "Failed password for user {user} from {ip} port {port}",
            "New connection from {ip} on interface eth0",
            "Firewall blocked connection from {ip} to port {port}",
            "CPU usage spike detected: {percent}%",
            "Suspicious process started: {process}",
            "File access denied: {path} for user {user}"
        ]
        
        users = ["root", "admin", "user", "www-data", "nobody"]
        ips = [f"192.168.1.{random.randint(1, 254)}" for _ in range(5)]
        ips.extend([f"10.0.0.{random.randint(1, 254)}" for _ in range(3)])
        ips.extend([f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(2)])
        
        processes = ["nginx", "apache2", "sshd", "cron", "python", "bash"]
        paths = ["/etc/passwd", "/etc/shadow", "/var/www/html", "/home/user/.ssh"]
        
        while self.active:
            log_template = random.choice(log_types)
            log_content = log_template.format(
                user=random.choice(users),
                ip=random.choice(ips),
                port=random.randint(1, 65535),
                percent=random.randint(70, 100),
                process=random.choice(processes),
                path=random.choice(paths)
            )
            
            source = random.choice(self.log_paths)
            yield {
                'timestamp': time.time(),
                'source': source,
                'content': log_content
            }
            
            # Random interval between logs
            await asyncio.sleep(random.uniform(0.1, 2.0))
            
    async def cleanup(self):
        """Cleanup resources"""
        self.active = False
        await asyncio.sleep(0)  # Yield to event loop
