import React, { useState, useEffect } from 'react';
import { fetchAnalytics } from '../api';

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
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('day'); // 'hour', 'day', 'week'

  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await fetchAnalytics();
        setAnalytics(data);
      } catch (error) {
        console.error('Error loading analytics data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, [timeRange]);

  if (loading && !analytics) {
    return <div className="p-6">Loading analytics data...</div>;
  }

  if (!analytics) {
    return <div className="p-6">No analytics data available</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-2">Analytics</h1>
        <p className="text-gray-600">System performance and security metrics</p>
      </div>

      <div className="flex gap-2 mb-6">
        <button 
          className={`px-4 py-2 rounded-md ${timeRange === 'hour' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setTimeRange('hour')}
        >
          Last Hour
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${timeRange === 'day' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setTimeRange('day')}
        >
          Last 24 Hours
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${timeRange === 'week' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setTimeRange('week')}
        >
          Last Week
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-white p-4 rounded-md shadow">
          <div className="text-sm text-gray-500">Total Alerts</div>
          <div className="text-2xl font-bold">{analytics.alerts_count}</div>
        </div>
        
        <div className="bg-white p-4 rounded-md shadow">
          <div className="text-sm text-gray-500">Network Packets</div>
          <div className="text-2xl font-bold">{analytics.network_packets_count.toLocaleString()}</div>
        </div>
        
        <div className="bg-white p-4 rounded-md shadow">
          <div className="text-sm text-gray-500">Log Entries</div>
          <div className="text-2xl font-bold">{analytics.total_log_entries.toLocaleString()}</div>
        </div>
      </div>

      {/* CPU & Memory Chart */}
      <div className="bg-white p-4 rounded-md shadow mb-6">
        <h2 className="text-lg font-semibold mb-4">System Performance</h2>
        <div className="h-60 flex items-center justify-center bg-gray-100 rounded">
          <p className="text-gray-500">CPU & Memory usage chart would be rendered here</p>
          {/* In a complete implementation, you would use a charting library to visualize the time_series data */}
        </div>
      </div>

      {/* Network Traffic Analysis */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-white p-4 rounded-md shadow">
          <h2 className="text-lg font-semibold mb-4">Protocol Distribution</h2>
          <div className="h-60">
            <ul className="space-y-2">
              {analytics.network.protocols.map((protocol, index) => (
                <li key={index} className="flex justify-between">
                  <span>{protocol.name}</span>
                  <span className="font-bold">{protocol.value.toLocaleString()} packets</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-md shadow">
          <h2 className="text-lg font-semibold mb-4">Top Ports</h2>
          <div className="h-60">
            <ul className="space-y-2">
              {analytics.network.top_ports.map((port, index) => (
                <li key={index} className="flex justify-between">
                  <span>Port {port.port}</span>
                  <span className="font-bold">{port.count.toLocaleString()} connections</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;