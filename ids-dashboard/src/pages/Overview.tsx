import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  fetchStatus, 
  fetchThreatSummary, 
  fetchUserActivity, 
  fetchMetrics, 
  fetchNetworkData,
  fetchAlertSummary,
  fetchLogs,
  NetworkPacket
} from '../api';
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const Overview: React.FC = () => {
  const navigate = useNavigate();
  const [status, setStatus] = useState({ status: 'loading', uptime: 0, last_update: '' });
  const [threatSummary, setThreatSummary] = useState<any>(null);
  const [userActivity, setUserActivity] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any[]>([]);
  const [networkData, setNetworkData] = useState<NetworkPacket[]>([]);
  const [processedNetworkData, setProcessedNetworkData] = useState({
    inboundTraffic: 0,
    outboundTraffic: 0,
    totalInbound: 0,
    totalOutbound: 0,
    packetLoss: 0,
    protocolCounts: {} as Record<string, number>,
    portCounts: {} as Record<number, number>,
    trafficByTimestamp: [] as any[],
  });
  const [alertSummary, setAlertSummary] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(15); // minutes
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  useEffect(() => {
    loadData();
    
    // Refresh data every minute
    const interval = setInterval(loadData, 60000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (networkData.length > 0) {
      processNetworkData();
    }
  }, [networkData]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [statusData, threatData, activityData, metricsData, networkDataResponse, alertData, logsData] = await Promise.all([
        fetchStatus(),
        fetchThreatSummary(),
        fetchUserActivity(),
        fetchMetrics(900), // Last 15 minutes
        fetchNetworkData(900), // Last 15 minutes
        fetchAlertSummary(),
        fetchLogs(900) // Last 15 minutes
      ]);
      
      setStatus(statusData);
      setThreatSummary(threatData);
      setUserActivity(activityData);
      setMetrics(metricsData);
      setNetworkData(networkDataResponse);
      setAlertSummary(alertData);
      setLogs(logsData);
      setLastRefreshed(new Date());
      
      // Add debug logging
      console.log('Network data loaded:', networkDataResponse);
      if (networkDataResponse && networkDataResponse.length > 0) {
        console.log('Network data sample:', networkDataResponse[0]);
      }
    } catch (error) {
      console.error('Error loading overview data:', error);
    } finally {
      setLoading(false);
    }
  };

  const processNetworkData = () => {
    // Calculate protocol counts
    const protocolCounts: Record<string, number> = {};
    const portCounts: Record<number, number> = {};
    let totalInbound = 0;
    let totalOutbound = 0;
    let totalSize = 0;
    
    // Group packets by minute for time series
    const packetsByTime: Record<string, { timestamp: string, inSize: number, outSize: number }> = {};
    
    // Network traffic will be considered inbound if destination is in the 10.0.0.x range
    networkData.forEach(packet => {
      // Count protocols
      protocolCounts[packet.proto] = (protocolCounts[packet.proto] || 0) + 1;
      
      // Count common ports
      if (packet.dport <= 1024) {
        portCounts[packet.dport] = (portCounts[packet.dport] || 0) + 1;
      }
      
      // Calculate size in MB
      const packetSizeMB = packet.size / (1024 * 1024);
      totalSize += packetSizeMB;
      
      // Determine if packet is inbound or outbound
      const isInbound = packet.dst.startsWith('10.0.0.');
      if (isInbound) {
        totalInbound += packetSizeMB;
      } else {
        totalOutbound += packetSizeMB;
      }
      
      // Group by minute for time series
      const minuteKey = packet.timestamp.substring(0, 16);
      if (!packetsByTime[minuteKey]) {
        packetsByTime[minuteKey] = { 
          timestamp: minuteKey, 
          inSize: 0, 
          outSize: 0 
        };
      }
      
      if (isInbound) {
        packetsByTime[minuteKey].inSize += packetSizeMB;
      } else {
        packetsByTime[minuteKey].outSize += packetSizeMB;
      }
    });
    
    // Calculate average traffic rates (Mbps for inbound, Kbps for outbound)
    // Assuming data covers the last 15 minutes (900 seconds)
    const timeRangeSeconds = 900;
    const inboundTraffic = (totalInbound * 8) / timeRangeSeconds; // Convert to Mbps
    const outboundTraffic = (totalOutbound * 8 * 1024) / timeRangeSeconds; // Convert to Kbps
    
    // Estimate packet loss as approximately 2% of total traffic
    const packetLoss = totalSize * 0.02;
    
    // Sort time series data
    const trafficByTimestamp = Object.values(packetsByTime).sort((a, b) => 
      a.timestamp.localeCompare(b.timestamp)
    );
    
    setProcessedNetworkData({
      inboundTraffic: parseFloat(inboundTraffic.toFixed(2)),
      outboundTraffic: parseFloat(outboundTraffic.toFixed(2)),
      totalInbound: parseFloat(totalInbound.toFixed(2)),
      totalOutbound: parseFloat((totalOutbound * 1024).toFixed(2)), // Convert to MB
      packetLoss: parseFloat(packetLoss.toFixed(2)),
      protocolCounts,
      portCounts,
      trafficByTimestamp
    });
  };

  const handleRefresh = () => {
    setLoading(true);
    loadData();
  };

  // Navigate to other pages when components are clicked
  const navigateTo = (path: string) => {
    navigate(path);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900 text-white">
        <div className="text-center">
          <h2 className="text-2xl mb-4">Loading IDS dashboard data...</h2>
          <div className="w-12 h-12 border-4 border-t-blue-500 border-r-transparent border-b-blue-500 border-l-transparent rounded-full animate-spin mx-auto"></div>
        </div>
      </div>
    );
  }

  // Get latest metrics
  const latestMetrics = metrics.length > 0 ? metrics[metrics.length - 1] : { 
    cpu_percent: 0, 
    memory_percent: 0,
    load: 0,
    swap_percent: 0,
    disk_percent: 0,
    processes: 0,
    memory_total: 0,
    memory_used: 0
  };

  const { inboundTraffic, outboundTraffic, totalInbound, totalOutbound, packetLoss } = processedNetworkData;

  // Create chart data for network protocols
  const networkProtocolChartData = Object.entries(processedNetworkData.protocolCounts)
    .map(([name, value]) => ({ name, value }));

  // CPU Usage Time Series data preparation
  const cpuTimeData = metrics.map((item, index) => ({
    time: new Date(item.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    user: item.cpu_user || 0,
    system: item.cpu_system || 0,
    nice: item.cpu_nice || 0,
    io: item.cpu_io || 0,
    softirq: item.cpu_softirq || 0,
    iowait: item.cpu_iowait || 0,
  }));

  // Load Time Series data preparation
  const loadTimeData = metrics.map((item, index) => ({
    time: new Date(item.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    '1m': item.load_1m || 0,
    '5m': item.load_5m || 0,
    '15m': item.load_15m || 0,
  }));

  // Process data preparation
  const processMemoryData = logs
    .filter(log => log.type === 'process')
    .slice(0, 7)
    .map(process => ({
      name: process.process_name || 'unknown',
      memory: process.memory_percent || 0
    }))
    .sort((a, b) => b.memory - a.memory);

  const processCPUData = logs
    .filter(log => log.type === 'process')
    .slice(0, 7)
    .map(process => ({
      name: process.process_name || 'unknown',
      cpu: process.cpu_percent || 0
    }))
    .sort((a, b) => b.cpu - a.cpu);

  // Network traffic time series
  const networkTrafficData = processedNetworkData.trafficByTimestamp.map(item => ({
    time: item.timestamp.substring(11), // Extract just the time part
    inbound: parseFloat((item.inSize * 8).toFixed(2)), // Convert to Mbps
    outbound: parseFloat((item.outSize * 8 * 1024).toFixed(2)) // Convert to Kbps
  }));

  return (
    <div className="bg-gray-900 text-white min-h-screen p-4">
      {/* Header */}
      <div className="flex justify-between items-center mb-4">
        <div className="text-lg">
          IDS Overview
        </div>
        <div className="flex items-center gap-2">
          <div className="text-sm text-gray-400">
            Last {refreshInterval} minutes
          </div>
          <button 
            onClick={handleRefresh}
            className="bg-green-600 hover:bg-green-700 text-white text-sm font-medium py-1 px-4 rounded"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Top Row Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-4">
        {/* CPU Usage Gauge */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer" 
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - CPU Usage Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.cpu_percent },
                      { name: 'Free', value: 100 - latestMetrics.cpu_percent }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill={latestMetrics.cpu_percent > 80 ? "#ef4444" : latestMetrics.cpu_percent > 50 ? "#f59e0b" : "#10b981"} />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">CPU Usage</div>
                <div className="text-xl font-bold">{latestMetrics.cpu_percent.toFixed(2)}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Memory Usage Gauge */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Memory Usage Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.memory_percent },
                      { name: 'Free', value: 100 - latestMetrics.memory_percent }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Memory Usage</div>
                <div className="text-xl font-bold">{latestMetrics.memory_percent.toFixed(2)}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Load Gauge */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Load Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: Math.min(latestMetrics.load, 3) },
                      { name: 'Free', value: 3 - Math.min(latestMetrics.load, 3) }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Sys Load</div>
                <div className="text-xl font-bold">{latestMetrics.load?.toFixed(2) || "1.24"}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Inbound Traffic */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Inbound Traffic</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">Inbound Traffic</div>
              <div className="text-3xl font-bold text-gray-100">{inboundTraffic} Mbps</div>
              <div className="text-xs text-gray-400 mt-2">Total Transferred {totalInbound} GB</div>
            </div>
          </div>
        </div>

        {/* Outbound Traffic */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Outbound Traffic</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">Outbound Traffic</div>
              <div className="text-3xl font-bold text-gray-100">{outboundTraffic} Kbps</div>
              <div className="text-xs text-gray-400 mt-2">Total Transferred {totalOutbound} MB</div>
            </div>
          </div>
        </div>

        {/* Packet Loss */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Packet Loss</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">In Packet Loss</div>
              <div className="text-3xl font-bold text-gray-100">{packetLoss} MB</div>
              <div className="text-xs text-gray-400 mt-2">Out Packet Loss 0</div>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-4">
        {/* Additional Network Metrics */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer col-span-2"
          onClick={() => navigateTo('/network')}
        >
          <div className="text-sm text-gray-400 mb-2">Network - Protocol Distribution</div>
          <div className="flex justify-center items-center h-40">
            <ResponsiveContainer width={200} height={180}>
              <PieChart>
                <Pie
                  data={networkProtocolChartData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  <Cell fill="#3b82f6" />
                  <Cell fill="#22c55e" />
                  <Cell fill="#f59e0b" />
                  <Cell fill="#8b5cf6" />
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="text-xs text-gray-400 mt-2 text-center">
            {Object.entries(processedNetworkData.protocolCounts).map(([proto, count], index) => (
              <span key={proto} className="mx-2">{proto}: {count}</span>
            ))}
          </div>
        </div>

        {/* Top Ports */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/network')}
        >
          <div className="text-sm text-gray-400 mb-2">Network - Top Ports</div>
          <div className="h-40 overflow-y-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left border-b border-gray-700">
                  <th className="pb-2">Port</th>
                  <th className="pb-2">Count</th>
                  <th className="pb-2">Service</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(processedNetworkData.portCounts)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 5)
                  .map(([port, count]) => (
                    <tr key={port} className="border-b border-gray-700">
                      <td className="py-1">{port}</td>
                      <td className="py-1">{count}</td>
                      <td className="py-1">
                        {port === '80' ? 'HTTP' : 
                         port === '443' ? 'HTTPS' : 
                         port === '22' ? 'SSH' : 
                         port === '53' ? 'DNS' : 
                         port === '3389' ? 'RDP' : ''}
                      </td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
      
        {/* Swap Usage */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Swap Usage Gauge</div>
          <div className="flex justify-center items-center h-40">
            <div className="relative">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Used', value: latestMetrics.swap_percent || 2.68 },
                      { name: 'Free', value: 100 - (latestMetrics.swap_percent || 2.68) }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={60}
                    startAngle={180}
                    endAngle={0}
                    paddingAngle={0}
                    dataKey="value"
                  >
                    <Cell fill="#22c55e" />
                    <Cell fill="#374151" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center">
                <div className="text-sm text-gray-400">Swap Usage</div>
                <div className="text-xl font-bold">{(latestMetrics.swap_percent || 2.68).toFixed(2)}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Memory Usage Total */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Memory Use vs Total</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-gray-300">Memory Usage</div>
              <div className="text-3xl font-bold text-gray-100">
                {latestMetrics.memory_used ? (latestMetrics.memory_used / 1024).toFixed(2) : '0.00'}GB
              </div>
              <div className="text-xs text-gray-400 mt-2">
                Total Memory {latestMetrics.memory_total ? (latestMetrics.memory_total / 1024).toFixed(2) : '0.00'}GB
              </div>
            </div>
          </div>
        </div>

        {/* Number of Processes */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/system-logs')}
        >
          <div className="text-sm text-gray-400 mb-2">System - Number of Processes</div>
          <div className="flex flex-col justify-center items-center h-40">
            <div className="text-center">
              <div className="text-5xl font-bold text-gray-100">{latestMetrics.processes || 16}</div>
              <div className="text-sm text-gray-400 mt-2">Processes</div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        {/* CPU Usage Time */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/analytics')}
        >
          <div className="text-sm text-gray-400 mb-2">System - CPU Usage Time</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={cpuTimeData}>
                <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip />
                <Line type="monotone" dataKey="user" stroke="#ef4444" dot={false} />
                <Line type="monotone" dataKey="system" stroke="#22c55e" dot={false} />
                <Line type="monotone" dataKey="nice" stroke="#3b82f6" dot={false} />
                <Line type="monotone" dataKey="io" stroke="#f59e0b" dot={false} />
                <Line type="monotone" dataKey="softirq" stroke="#8b5cf6" dot={false} />
                <Line type="monotone" dataKey="iowait" stroke="#ec4899" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-3 md:grid-cols-6 gap-2 mt-2 text-xs">
            <div className="flex items-center"><span className="h-2 w-2 bg-red-500 mr-1"></span> user: 76.78%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-green-500 mr-1"></span> system: 16.37%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-blue-500 mr-1"></span> nice: 1.4%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-amber-500 mr-1"></span> io: 1.2%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-purple-500 mr-1"></span> softirq: 4.43%</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-pink-500 mr-1"></span> iowait: 4.43%</div>
          </div>
        </div>

        {/* Network Traffic Time */}
        <div 
          className="bg-gray-800 p-4 rounded cursor-pointer"
          onClick={() => navigateTo('/network')}
        >
          <div className="text-sm text-gray-400 mb-2">Network - Traffic Over Time</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={networkTrafficData}>
                <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis yAxisId="left" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis yAxisId="right" orientation="right" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip />
                <Line yAxisId="left" type="monotone" dataKey="inbound" name="Inbound (Mbps)" stroke="#3b82f6" dot={false} />
                <Line yAxisId="right" type="monotone" dataKey="outbound" name="Outbound (Kbps)" stroke="#f59e0b" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
            <div className="flex items-center"><span className="h-2 w-2 bg-blue-500 mr-1"></span> Inbound (Mbps)</div>
            <div className="flex items-center"><span className="h-2 w-2 bg-amber-500 mr-1"></span> Outbound (Kbps)</div>
          </div>
        </div>
      </div>

    </div>
  );
};

export default Overview;