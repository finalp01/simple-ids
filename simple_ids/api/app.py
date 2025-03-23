from flask import Flask, jsonify, request
from flask_cors import CORS
import asyncio
import threading
import time
import json
import os
from datetime import datetime, timedelta

#core IDS components
from simple_ids.collectors.data_collector import DataCollector
from simple_ids.analyzers.analyzer import AnalyzerEngine
from simple_ids.alerts.alert_handler import AlertHandler

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Create global variables for IDS components
collector = None
analyzer = None
alert_handler = None
ids_thread = None
is_running = False

# In-memory cache to reduce direct queries to collector/analyzer
data_cache = {
    'last_update': 0,
    'refresh_interval': 1,  # seconds
    'metrics': [],
    'network': [],
    'logs': [],
    'alerts': []
}

def get_recent_data(data_list, seconds=60):
    """Filter data to get only recent entries"""
    now = time.time()
    cutoff = now - seconds
    return [item for item in data_list if item.get('timestamp', 0) > cutoff]

def format_timestamp(timestamp):
    """Convert unix timestamp to human readable format"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def update_cache():
    """Update the data cache from collectors and analyzers"""
    global data_cache
    
    now = time.time()
    if now - data_cache['last_update'] < data_cache['refresh_interval']:
        return
    
    # Create event loop for async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Get the latest data
        collected_data = loop.run_until_complete(collector.get_collected_data())
        alerts = loop.run_until_complete(analyzer.get_alerts())
        
        # Update cache
        data_cache['metrics'] = collected_data['metrics']
        data_cache['network'] = collected_data['network']
        data_cache['logs'] = collected_data['logs']
        data_cache['alerts'] = alerts
        data_cache['last_update'] = now
    finally:
        loop.close()

def run_ids():
    """Run the IDS in a separate thread"""
    global is_running, collector, analyzer, alert_handler
    
    # Create event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Initialize components
        collector = DataCollector()
        analyzer = AnalyzerEngine(collector)
        alert_handler = AlertHandler()
        
        # Create and run tasks
        collection_task = loop.create_task(collector.collect_all_data())
        analysis_task = loop.create_task(analyzer.start_analysis())
        
        is_running = True
        loop.run_forever()
    except Exception as e:
        print(f"Error in IDS thread: {str(e)}")
    finally:
        # Clean up
        if collector:
            loop.run_until_complete(collector.cleanup())
        if analyzer:
            loop.run_until_complete(analyzer.cleanup())
        loop.close()
        is_running = False

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current IDS status"""
    return jsonify({
        'status': 'running' if is_running else 'stopped',
        'uptime': int(time.time() - data_cache.get('start_time', time.time())),
        'last_update': format_timestamp(data_cache['last_update']) if data_cache['last_update'] > 0 else 'Never'
    })

@app.route('/api/start', methods=['POST'])
def start_ids():
    """Start the IDS"""
    global ids_thread, is_running, data_cache
    
    if is_running:
        return jsonify({'status': 'already_running', 'message': 'IDS is already running'})
    
    data_cache['start_time'] = time.time()
    ids_thread = threading.Thread(target=run_ids)
    ids_thread.daemon = True
    ids_thread.start()
    
    # Give IDS time to initialize
    time.sleep(1)
    
    return jsonify({'status': 'started', 'message': 'IDS started successfully'})

@app.route('/api/stop', methods=['POST'])
def stop_ids():
    """Stop the IDS"""
    global is_running
    
    if not is_running:
        return jsonify({'status': 'not_running', 'message': 'IDS is not running'})
    
    # Signal IDS to stop
    is_running = False
    
    # Create event loop for async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        if collector:
            loop.run_until_complete(collector.cleanup())
        if analyzer:
            loop.run_until_complete(analyzer.cleanup())
    finally:
        loop.close()
    
    return jsonify({'status': 'stopped', 'message': 'IDS stopped successfully'})

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get system metrics data"""
    update_cache()
    
    # Get time range from query parameters
    time_range = int(request.args.get('range', 60))  # Default to last 60 seconds
    
    metrics_data = get_recent_data(data_cache['metrics'], time_range)
    
    # Format data for the dashboard
    formatted_metrics = []
    for m in metrics_data:
        formatted_metrics.append({
            'timestamp': format_timestamp(m.get('timestamp', 0)),
            'cpu_percent': m.get('cpu_percent', 0),
            'memory_percent': m.get('memory_percent', 0),
            'disk_io': m.get('disk_io', {}),
            'network_io': m.get('network_io', {}),
            'connections': m.get('connections', 0),
            'processes': m.get('processes', 0)
        })
    
    return jsonify(formatted_metrics)

@app.route('/api/network', methods=['GET'])
def get_network():
    """Get network traffic data"""
    update_cache()
    
    # Get time range from query parameters
    time_range = int(request.args.get('range', 60))  # Default to last 60 seconds
    
    network_data = get_recent_data(data_cache['network'], time_range)
    
    # Format data for the dashboard
    formatted_network = []
    for n in network_data:
        formatted_network.append({
            'timestamp': format_timestamp(n.get('timestamp', 0)),
            'src': n.get('src', ''),
            'dst': n.get('dst', ''),
            'proto': n.get('proto', ''),
            'size': n.get('size', 0),
            'flags': n.get('flags', ''),
            'sport': n.get('sport', 0),
            'dport': n.get('dport', 0)
        })
    
    return jsonify(formatted_network)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get system logs data"""
    update_cache()
    
    # Get time range from query parameters
    time_range = int(request.args.get('range', 3600))  # Default to last hour
    
    logs_data = get_recent_data(data_cache['logs'], time_range)
    
    # Format data for the dashboard
    formatted_logs = []
    for log in logs_data:
        formatted_logs.append({
            'timestamp': format_timestamp(log.get('timestamp', 0)),
            'source': log.get('source', ''),
            'content': log.get('content', '')
        })
    
    return jsonify(formatted_logs)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    update_cache()
    
    # Get all alerts from analyzer
    alerts_data = data_cache['alerts']
    
    # Format data for the dashboard
    formatted_alerts = []
    for alert in alerts_data:
        formatted_alerts.append({
            'timestamp': format_timestamp(alert.get('timestamp', 0)),
            'type': alert.get('type', ''),
            'severity': alert.get('severity', ''),
            'source': alert.get('source', ''),
            'description': alert.get('description', '')
        })
    
    return jsonify(formatted_alerts)

@app.route('/api/alert-summary', methods=['GET'])
def get_alert_summary():
    """Get summary of alerts"""
    if not alert_handler:
        return jsonify({
            'total_alerts': 0,
            'by_type': {},
            'by_severity': {}
        })
    
    # Create event loop for async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        summary = loop.run_until_complete(alert_handler.get_alert_summary())
    finally:
        loop.close()
    
    return jsonify(summary)

@app.route('/api/threat-summary', methods=['GET'])
def get_threat_summary():
    """Get summary of threats detected"""
    update_cache()
    
    # Calculate time periods
    now = time.time()
    last_hour = now - 3600
    last_day = now - 86400
    
    # Get alerts from different time periods
    alerts_hour = [a for a in data_cache['alerts'] if a.get('timestamp', 0) > last_hour]
    alerts_day = [a for a in data_cache['alerts'] if a.get('timestamp', 0) > last_day]
    
    # Count by severity
    severity_counts = {
        'high': len([a for a in alerts_hour if a.get('severity') == 'high']),
        'medium': len([a for a in alerts_hour if a.get('severity') == 'medium']),
        'warning': len([a for a in alerts_hour if a.get('severity') == 'warning']),
        'low': len([a for a in alerts_hour if a.get('severity') == 'low'])
    }
    
    # Get top threat types
    threat_types = {}
    for alert in alerts_day:
        alert_type = alert.get('type', 'Unknown')
        threat_types[alert_type] = threat_types.get(alert_type, 0) + 1
    
    # Sort by count
    top_threats = sorted(
        [{'type': t, 'count': c} for t, c in threat_types.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:5]  # Top 5
    
    return jsonify({
        'total_alerts': len(data_cache['alerts']),
        'alerts_last_hour': len(alerts_hour),
        'alerts_last_day': len(alerts_day),
        'severity_counts': severity_counts,
        'top_threats': top_threats
    })

@app.route('/api/user-activity', methods=['GET'])
def get_user_activity():
    """Get summary of user activity"""
    update_cache()
    
    # Extract user-related activity from logs
    user_activity = []
    
    for log in data_cache['logs']:
        content = log.get('content', '')
        timestamp = log.get('timestamp', 0)
        
        # Look for user-related events in logs
        user_match = None
        activity_type = None
        
        if 'login' in content.lower() or 'logged in' in content.lower():
            user_match = content
            activity_type = 'login'
        elif 'logout' in content.lower() or 'logged out' in content.lower():
            user_match = content
            activity_type = 'logout'
        elif 'authentication' in content.lower():
            user_match = content
            activity_type = 'authentication'
        elif 'user' in content.lower() and ('created' in content.lower() or 'added' in content.lower()):
            user_match = content
            activity_type = 'user_creation'
        
        if user_match and activity_type:
            # Extract username if possible
            username = 'unknown'
            username_match = None
            
            if 'user' in content.lower():
                username_match = content.lower().split('user')[1].split()[0].strip()
            
            if username_match:
                username = username_match
            
            user_activity.append({
                'timestamp': format_timestamp(timestamp),
                'user': username,
                'activity': activity_type,
                'details': content
            })
    
    return jsonify(user_activity)

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data for dashboard visualizations"""
    update_cache()
    
    # Time range boundaries
    now = time.time()
    last_hour = now - 3600
    
    # Process metrics data for charts
    metrics_data = [m for m in data_cache['metrics'] if m.get('timestamp', 0) > last_hour]
    
    # Prepare time series data
    cpu_series = []
    memory_series = []
    timestamps = []
    
    for m in metrics_data:
        timestamps.append(format_timestamp(m.get('timestamp', 0)))
        cpu_series.append(m.get('cpu_percent', 0))
        memory_series.append(m.get('memory_percent', 0))
    
    # Network traffic analysis
    network_data = [n for n in data_cache['network'] if n.get('timestamp', 0) > last_hour]
    
    # Group by protocol
    proto_counts = {}
    for packet in network_data:
        proto = packet.get('proto', 'unknown')
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
    
    proto_series = [{'name': proto, 'value': count} for proto, count in proto_counts.items()]
    
    # Port activity
    port_counts = {}
    for packet in network_data:
        port = packet.get('dport', 0)
        if port > 0:
            port_counts[port] = port_counts.get(port, 0) + 1
    
    # Get top 10 ports
    top_ports = sorted(
        [{'port': port, 'count': count} for port, count in port_counts.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:10]
    
    return jsonify({
        'time_series': {
            'timestamps': timestamps,
            'cpu': cpu_series,
            'memory': memory_series
        },
        'network': {
            'protocols': proto_series,
            'top_ports': top_ports
        },
        'alerts_count': len(data_cache['alerts']),
        'network_packets_count': len(network_data),
        'total_log_entries': len(data_cache['logs'])
    })

if __name__ == '__main__':
    print("Starting IDS API Server...")
    # Start IDS on server start
    with app.app_context():
        start_ids()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
