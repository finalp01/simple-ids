const API_BASE_URL = 'http://localhost:5000/api';

// Helper function for API calls
async function apiCall<T>(endpoint: string, method: string = 'GET', body?: any): Promise<T> {
  const options: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
    },
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }
  
  return response.json();
}

// API functions
export const fetchStatus = () => apiCall<{ status: string; uptime: number; last_update: string }>('/status');

export const startIDS = () => apiCall<{ status: string; message: string }>('/start', 'POST');

export const stopIDS = () => apiCall<{ status: string; message: string }>('/stop', 'POST');

export const fetchMetrics = (range: number = 300) => 
  apiCall<any[]>(`/metrics?range=${range}`);

// Updated network data fetch function with better typing
export interface NetworkPacket {
  dport: number;
  dst: string;
  flags: string;
  proto: string;
  size: number;
  sport: number;
  src: string;
  timestamp: string;
}

export const fetchNetworkData = (range: number = 300) => 
  apiCall<NetworkPacket[]>(`/network?range=${range}`);

// For network summary statistics
export interface NetworkSummary {
  incoming_mbps: number;
  outgoing_mbps: number;
  total_incoming_gb: number;
  total_outgoing_mb: number;
  packet_loss_mb: number;
}

export const fetchNetworkSummary = (range: number = 300) => 
  apiCall<NetworkSummary>(`/network-summary?range=${range}`);

export const fetchLogs = (range: number = 3600) => 
  apiCall<any[]>(`/logs?range=${range}`);

export const fetchAlerts = () => 
  apiCall<any[]>('/alerts');

export const fetchAlertSummary = () => 
  apiCall<{ total_alerts: number; by_type: Record<string, number>; by_severity: Record<string, number> }>('/alert-summary');

export const fetchThreatSummary = () => 
  apiCall<{
    total_alerts: number;
    alerts_last_hour: number;
    alerts_last_day: number;
    severity_counts: Record<string, number>;
    top_threats: Array<{ type: string; count: number }>;
  }>('/threat-summary');

export const fetchUserActivity = () => 
  apiCall<any[]>('/user-activity');

export const fetchAnalytics = () => 
  apiCall<{
    time_series: {
      timestamps: string[];
      cpu: number[];
      memory: number[];
    };
    network: {
      protocols: Array<{ name: string; value: number }>;
      top_ports: Array<{ port: number; count: number }>;
    };
    alerts_count: number;
    network_packets_count: number;
    total_log_entries: number;
  }>('/analytics');