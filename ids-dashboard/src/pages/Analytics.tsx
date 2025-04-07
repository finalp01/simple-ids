import React, { useState, useEffect } from 'react';
import { fetchAnalytics, fetchAlerts, fetchNetworkData, fetchMetrics, NetworkPacket } from '../api';
import { 
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, 
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  AreaChart, Area, ScatterChart, Scatter
} from 'recharts';

interface Analytics {
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
}

const Analytics: React.FC = () => {
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [alertsData, setAlertsData] = useState<any[]>([]);
  const [networkData, setNetworkData] = useState<NetworkPacket[]>([]);
  const [processedNetworkData, setProcessedNetworkData] = useState<any>({
    protocols: [],
    topPorts: [],
    trafficOverTime: [],
    sourceDest: [],
    flagDistribution: []
  });
  const [metricsData, setMetricsData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [timeRange, setTimeRange] = useState('day'); // 'hour', 'day', 'week'
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Convert timeRange to seconds for API calls
  const timeRangeInSeconds = {
    'hour': 3600,
    'day': 86400,
    'week': 604800
  }[timeRange];

  // Default data to allow UI to render immediately even when API data isn't ready
  const defaultAnalytics: Analytics = {
    time_series: { timestamps: [], cpu: [], memory: [] },
    network: { protocols: [], top_ports: [] },
    alerts_count: 0,
    network_packets_count: 0,
    total_log_entries: 0,
  };

  // Process network data from API into visualizable format
  const processNetworkData = (rawData: NetworkPacket[]) => {
    if (!rawData || rawData.length === 0) return;
    
    // Process protocol distribution
    const protocolCounts: Record<string, number> = {};
    rawData.forEach(packet => {
      const proto = packet.proto || 'Unknown';
      protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
    });
    
    const protocols = Object.entries(protocolCounts).map(([name, value]) => ({
      name,
      value
    }));
    
    // Process top ports
    const portCounts: Record<number, number> = {};
    rawData.forEach(packet => {
      const port = packet.dport;
      portCounts[port] = (portCounts[port] || 0) + 1;
    });
    
    const topPorts = Object.entries(portCounts)
      .map(([port, count]) => ({ port: parseInt(port), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    
    // Process traffic over time
    // Group packets by minute
    const trafficByTime: Record<string, { timestamp: string, inbound: number, outbound: number, packetCount: number }> = {};
    
    rawData.forEach(packet => {
      const timestamp = new Date(packet.timestamp);
      // Format as YYYY-MM-DD HH:MM to group by minute
      const timeKey = timestamp.toISOString().slice(0, 16);
      
      if (!trafficByTime[timeKey]) {
        trafficByTime[timeKey] = {
          timestamp: timestamp.toLocaleTimeString('en-US', { 
            hour: 'numeric', 
            minute: '2-digit' 
          }),
          inbound: 0,
          outbound: 0,
          packetCount: 0
        };
      }
      
      // Convert packet size from bytes to MB
      const sizeInMB = packet.size / (1024 * 1024);
      
      // Classify as inbound or outbound based on destination
      if (packet.dst.startsWith('10.0.0.')) {
        trafficByTime[timeKey].inbound += sizeInMB;
      } else {
        trafficByTime[timeKey].outbound += sizeInMB;
      }
      
      trafficByTime[timeKey].packetCount += 1;
    });
    
    const trafficOverTime = Object.values(trafficByTime).sort((a, b) => 
      a.timestamp.localeCompare(b.timestamp)
    );
    
    // Process source-destination pairs
    const sourceDest = rawData.map(packet => ({
      src: packet.src,
      dst: packet.dst,
      size: packet.size / 1024, // Convert to KB for better visualization
      proto: packet.proto
    })).slice(0, 100); // Limit to prevent overwhelm
    
    // Process TCP flags distribution
    const flagCounts: Record<string, number> = {};
    rawData.forEach(packet => {
      const flag = packet.flags || 'None';
      flagCounts[flag] = (flagCounts[flag] || 0) + 1;
    });
    
    const flagDistribution = Object.entries(flagCounts).map(([name, value]) => ({
      name: name || 'None',
      value
    }));
    
    // Update state with processed data
    setProcessedNetworkData({
      protocols,
      topPorts,
      trafficOverTime,
      sourceDest,
      flagDistribution
    });
  };

  // A helper function to load each API call separately
  const loadData = () => {
    // Set loading to false quickly so UI renders immediately.
    setLoading(false);

    // Fetch analytics data
    fetchAnalytics()
      .then(data => {
        setAnalytics(data);
        setLastRefreshed(new Date());
      })
      .catch(error => console.error('Error fetching analytics:', error));

    // Fetch alerts data
    fetchAlerts()
      .then(data => setAlertsData(data))
      .catch(error => console.error('Error fetching alerts:', error));

    // Fetch network data
    fetchNetworkData(timeRangeInSeconds)
      .then(data => {
        setNetworkData(data);
        processNetworkData(data);
      })
      .catch(error => console.error('Error fetching network data:', error));

    // Fetch metrics data
    fetchMetrics(timeRangeInSeconds)
      .then(data => setMetricsData(data))
      .catch(error => console.error('Error fetching metrics:', error));
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, [timeRange, timeRangeInSeconds]);

  useEffect(() => {
    // Process network data when it changes
    processNetworkData(networkData);
  }, [networkData]);

  const handleRefresh = () => {
    loadData();
  };

  // Use default analytics if the data hasn't loaded yet so that the UI still renders
  const displayAnalytics = analytics || defaultAnalytics;

  // Prepare data for visualizations
  const COLORS = ['#22c55e', '#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#ec4899'];

  // Protocol distribution for pie chart
  const protocolData = processedNetworkData.protocols.length > 0 
    ? processedNetworkData.protocols 
    : displayAnalytics.network.protocols.map((protocol) => ({
        name: protocol.name,
        value: protocol.value
      }));

  // Top ports data
  const portsData = processedNetworkData.topPorts.length > 0
    ? processedNetworkData.topPorts.map((port:any) => ({
        name: `Port ${port.port}`,
        value: port.count
      }))
    : displayAnalytics.network.top_ports.map((port) => ({
        name: `Port ${port.port}`,
        value: port.count
      }));

  // Prepare CPU & Memory time series data
  const systemPerformanceData = displayAnalytics.time_series.timestamps.map((timestamp, index) => ({
    time: new Date(timestamp).toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit',
      month: 'short',
      day: 'numeric'
    }),
    cpu: displayAnalytics.time_series.cpu[index],
    memory: displayAnalytics.time_series.memory[index]
  }));

  // Prepare alert count by type
  const alertTypeData = alertsData.reduce((acc, alert) => {
    const alertType = alert.type || 'Unknown';
    if (!acc[alertType]) {
      acc[alertType] = 0;
    }
    acc[alertType]++;
    return acc;
  }, {} as Record<string, number>);

  const alertTypeChartData = Object.entries(alertTypeData).map(([type, count]) => ({
    name: type,
    value: count
  }));

  // Prepare alert severity distribution
  const alertSeverityData = alertsData.reduce((acc, alert) => {
    const severity = alert.severity || 'Unknown';
    if (!acc[severity]) {
      acc[severity] = 0;
    }
    acc[severity]++;
    return acc;
  }, {} as Record<string, number>);

  const alertSeverityChartData = Object.entries(alertSeverityData).map(([severity, count]) => ({
    name: severity,
    value: count
  }));

  // Network traffic over time
  const networkTrafficData = processedNetworkData.trafficOverTime.length > 0
    ? processedNetworkData.trafficOverTime
    : []; // Use empty array if no data yet

  // TCP Flags Distribution
  const flagDistributionData = processedNetworkData.flagDistribution;

  return (
    <div className="bg-gray-900 text-white min-h-screen p-4">
      {/* Header */}
      <div className="flex justify-between items-center mb-4">
        <div className="text-lg">
          Analytics Dashboard
        </div>
        <div className="flex items-center gap-2">
          <div className="text-sm text-gray-400">
            Last refreshed: {lastRefreshed.toLocaleTimeString()}
          </div>
          <button 
            onClick={handleRefresh}
            className="bg-green-600 hover:bg-green-700 text-white text-sm font-medium py-1 px-4 rounded"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Time Range Selection */}
      <div className="flex gap-2 mb-6">
        <button 
          className={`px-4 py-2 rounded ${timeRange === 'hour' ? 'bg-green-700 text-white' : 'bg-gray-700 text-gray-300'}`}
          onClick={() => setTimeRange('hour')}
        >
          Last Hour
        </button>
        <button 
          className={`px-4 py-2 rounded ${timeRange === 'day' ? 'bg-green-700 text-white' : 'bg-gray-700 text-gray-300'}`}
          onClick={() => setTimeRange('day')}
        >
          Last 24 Hours
        </button>
        <button 
          className={`px-4 py-2 rounded ${timeRange === 'week' ? 'bg-green-700 text-white' : 'bg-gray-700 text-gray-300'}`}
          onClick={() => setTimeRange('week')}
        >
          Last Week
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400">Total Alerts</div>
          <div className="text-3xl font-bold">{displayAnalytics.alerts_count}</div>
          <div className="text-xs text-gray-500 mt-1">
            {timeRange === 'hour' ? 'Last hour' : timeRange === 'day' ? 'Last 24 hours' : 'Last week'}
          </div>
        </div>
        
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400">Network Packets</div>
          <div className="text-3xl font-bold">{networkData.length || displayAnalytics.network_packets_count.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">Processed packets</div>
        </div>
        
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400">Log Entries</div>
          <div className="text-3xl font-bold">{displayAnalytics.total_log_entries.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">Total entries analyzed</div>
        </div>
      </div>

      {/* System Performance Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* CPU & Memory Chart */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">System Performance</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={systemPerformanceData}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="cpu" 
                  name="CPU (%)" 
                  stroke="#ef4444" 
                  dot={false} 
                  activeDot={{ r: 8 }} 
                />
                <Line 
                  type="monotone" 
                  dataKey="memory" 
                  name="Memory (%)" 
                  stroke="#22c55e" 
                  dot={false} 
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Network Traffic Chart */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">Network Traffic (MB/s)</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={networkTrafficData}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="timestamp" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                />
                <Legend />
                <Area 
                  type="monotone" 
                  dataKey="inbound" 
                  name="Inbound (MB/s)" 
                  stackId="1"
                  stroke="#3b82f6" 
                  fill="#3b82f6" 
                  fillOpacity={0.6}
                />
                <Area 
                  type="monotone" 
                  dataKey="outbound" 
                  name="Outbound (MB/s)" 
                  stackId="1"
                  stroke="#8b5cf6" 
                  fill="#8b5cf6" 
                  fillOpacity={0.6}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Network Analysis Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* Protocol Distribution */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">Protocol Distribution</div>
          <div className="grid grid-cols-2 gap-4">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {protocolData.map((entry:any, index:any) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                    formatter={(value) => [`${value} packets`, 'Count']}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div>
              <div className="text-sm mb-2">Protocol Details</div>
              <ul className="space-y-2 text-sm">
                {protocolData.map((protocol:any, index:any) => (
                  <li key={index} className="flex justify-between items-center">
                    <div className="flex items-center">
                      <span className="h-3 w-3 mr-2" style={{ backgroundColor: COLORS[index % COLORS.length] }}></span>
                      <span>{protocol.name}</span>
                    </div>
                    <span className="font-bold">{protocol.value.toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
        
        {/* Top Ports */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">Top Active Ports</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={portsData}
                layout="vertical"
                margin={{ top: 5, right: 30, left: 50, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis 
                  dataKey="name" 
                  type="category" 
                  tick={{ fill: '#9ca3af', fontSize: 10 }} 
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                  formatter={(value) => [`${value} connections`, 'Count']}
                />
                <Bar dataKey="value" fill="#22c55e">
                  {portsData.map((entry:any, index:any) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* New Network Analysis Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* TCP Flags Distribution */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">TCP Flags Distribution</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={flagDistributionData}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                  formatter={(value) => [`${value} packets`, 'Count']}
                />
                <Bar dataKey="value" fill="#f59e0b">
                  {flagDistributionData.map((entry:any, index:any) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        {/* Packet Size Distribution */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">Packet Size Distribution</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart
                margin={{ top: 20, right: 20, bottom: 20, left: 20 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  type="number" 
                  dataKey="size" 
                  name="Size (KB)" 
                  tick={{ fill: '#9ca3af', fontSize: 10 }}
                  label={{ value: 'Packet Size (KB)', position: 'insideBottom', offset: -5, fill: '#9ca3af' }}
                />
                <YAxis 
                  dataKey="index" 
                  type="number" 
                  name="Index" 
                  hide={true}
                />
                <Tooltip 
                  cursor={{ strokeDasharray: '3 3' }}
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                  formatter={(value:number, name, props) => {
                    if (name === 'Size (KB)') {
                      return [`${value.toFixed(2)} KB`, name];
                    }
                    return [value, name];
                  }}
                  labelFormatter={(value) => `Packet`}
                />
                <Scatter 
                  name="TCP" 
                  data={networkData
                    .filter(packet => packet.proto === 'TCP')
                    .map((packet, index) => ({ ...packet, size: packet.size / 1024, index }))}
                  fill="#ef4444"
                />
                <Scatter 
                  name="UDP" 
                  data={networkData
                    .filter(packet => packet.proto === 'UDP')
                    .map((packet, index) => ({ ...packet, size: packet.size / 1024, index: index + 1000 }))}
                  fill="#3b82f6"
                />
                <Scatter 
                  name="ICMP" 
                  data={networkData
                    .filter(packet => packet.proto === 'ICMP')
                    .map((packet, index) => ({ ...packet, size: packet.size / 1024, index: index + 2000 }))}
                  fill="#22c55e"
                />
                <Legend />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Alert Analysis Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* Alert Type Distribution */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">Alert Types</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={alertTypeChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                >
                  {alertTypeChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                  formatter={(value) => [`${value} alerts`, 'Count']}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        {/* Alert Severity Distribution */}
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">Alert Severity Distribution</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={alertSeverityChartData}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                  formatter={(value) => [`${value} alerts`, 'Count']}
                />
                <Bar dataKey="value" fill="#ef4444">
                  {alertSeverityChartData.map((entry, index) => {
                    // Color by severity - red for high, orange for medium, yellow for low
                    let color = '#ef4444'; // Red (High)
                    if (entry.name.toLowerCase() === 'medium') color = '#f59e0b';
                    if (entry.name.toLowerCase() === 'low') color = '#eab308';
                    
                    return <Cell key={`cell-${index}`} fill={color} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Network Traffic Table */}
      <div className="bg-gray-800 p-4 rounded shadow mb-6">
        <div className="text-sm text-gray-400 mb-2">Recent Network Packets</div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left text-gray-300">
            <thead className="text-xs text-gray-400 uppercase bg-gray-700">
              <tr>
                <th className="px-4 py-2">Time</th>
                <th className="px-4 py-2">Source</th>
                <th className="px-4 py-2">Destination</th>
                <th className="px-4 py-2">Protocol</th>
                <th className="px-4 py-2">Size</th>
                <th className="px-4 py-2">Src Port</th>
                <th className="px-4 py-2">Dst Port</th>
                <th className="px-4 py-2">Flags</th>
              </tr>
            </thead>
            <tbody>
              {networkData.slice(0, 10).map((packet, index) => (
                <tr key={index} className="border-b border-gray-700">
                  <td className="px-4 py-2">{new Date(packet.timestamp).toLocaleTimeString()}</td>
                  <td className="px-4 py-2">{packet.src}</td>
                  <td className="px-4 py-2">{packet.dst}</td>
                  <td className="px-4 py-2">{packet.proto}</td>
                  <td className="px-4 py-2">{(packet.size / 1024).toFixed(2)} KB</td>
                  <td className="px-4 py-2">{packet.sport}</td>
                  <td className="px-4 py-2">{packet.dport}</td>
                  <td className="px-4 py-2">{packet.flags || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      
      {/* Detailed Metrics */}
      <div className="grid grid-cols-1 gap-4">
        <div className="bg-gray-800 p-4 rounded shadow">
          <div className="text-sm text-gray-400 mb-2">System Metrics Timeline</div>
          <div className="h-96">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={metricsData.map(metric => ({
                  time: new Date(metric.timestamp).toLocaleTimeString('en-US', { 
                    hour: 'numeric', 
                    minute: '2-digit',
                    month: 'short',
                    day: 'numeric'
                  }),
                  cpu: metric.cpu_percent || 0,
                  memory: metric.memory_percent || 0,
                  disk: metric.disk_percent || 0,
                  swap: metric.swap_percent || 0,
                  load: metric.load || 0
                }))}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#4b5563', color: '#f9fafb' }}
                />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="cpu" 
                  name="CPU (%)" 
                  stroke="#ef4444" 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="memory" 
                  name="Memory (%)" 
                  stroke="#22c55e" 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="disk" 
                  name="Disk (%)" 
                  stroke="#3b82f6" 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="swap" 
                  name="Swap (%)" 
                  stroke="#8b5cf6" 
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="load" 
                  name="System Load" 
                  stroke="#f59e0b" 
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
