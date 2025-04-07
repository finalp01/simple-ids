import asyncio
from datetime import datetime
import platform
import os
import json

class AlertHandler:
    def __init__(self):
        self.os_type = platform.system()
        self.log_file = 'security_alerts.log'
        self.alert_count = 0
        self.alerts_enabled = True
        
    async def send_alert(self, alert):
        """Send system notification for alerts"""
        if not self.alerts_enabled:
            return
            
        # Increment alert counter
        self.alert_count += 1
        
        # Format alert message
        title = f"Security Alert: {alert.get('type', 'Unknown')}"
        message = f"Severity: {alert.get('severity', 'unknown')}\nSource: {alert.get('source', 'unknown')}"
        
        # Send notification
        await self._send_notification(title, message)
        
        # Log alert
        await self.log_alert(alert)
        
    async def _send_notification(self, title, message):
        """Send OS-specific notification"""
        try:
            if self.os_type == "Darwin":  # macOS
                os.system(f"""
                    osascript -e 'display notification "{message}" with title "{title}"'
                """)
            elif self.os_type == "Linux":
                # Requires notify-send (requires libnotify-bin)
                os.system(f'notify-send "{title}" "{message}"')
            elif self.os_type == "Windows":
                # Using Windows toast notifications
                try:
                    from win10toast_async import ToastNotifier
                    toaster = ToastNotifier()
                    await toaster.show_toast(title, message, duration=5)
                except ImportError:
                    print(f"[ALERT] {title}: {message}")
            else:
                # Fallback to console
                print(f"[ALERT] {title}: {message}")
                
        except Exception as e:
            print(f"Failed to send notification: {str(e)}")
            print(f"[ALERT] {title}: {message}")
            
    async def log_alert(self, alert):
        """Log alert to file for historical tracking"""
        timestamp = datetime.now().isoformat()
        alert_with_time = {
            'timestamp': timestamp,
            **alert
        }
        
        try:
            # Append JSON alert to log file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(alert_with_time) + '\n')
        except Exception as e:
            print(f"Failed to log alert: {str(e)}")
            
    def toggle_alerts(self, enabled=None):
        """Enable or disable alert notifications"""
        """Toggle alert notifications on/off"""
        if enabled is not None:
            self.alerts_enabled = enabled
        else:
            self.alerts_enabled = not self.alerts_enabled

        status = "enabled" if self.alerts_enabled else "disabled"
        print(f"Alert notifications {status}")
        return self.alerts_enabled

    async def get_alert_summary(self):
        """Get summary of alerts from log file"""
        try:
            if not os.path.exists(self.log_file):
                return {"total_alerts": 0, "by_type": {}, "by_severity": {}}

            alerts = []
            with open(self.log_file, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        alerts.append(alert)
                    except json.JSONDecodeError:
                        continue

            # Count by type
            by_type = {}
            for alert in alerts:
                alert_type = alert.get('type', 'unknown')
                by_type[alert_type] = by_type.get(alert_type, 0) + 1

            # Count by severity
            by_severity = {}
            for alert in alerts:
                severity = alert.get('severity', 'unknown')
                by_severity[severity] = by_severity.get(severity, 0) + 1

            return {
                "total_alerts": len(alerts),
                "by_type": by_type,
                "by_severity": by_severity
            }

        except Exception as e:
            print(f"Error getting alert summary: {str(e)}")
            return {"error": str(e)}


