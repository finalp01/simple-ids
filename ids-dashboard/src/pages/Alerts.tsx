import React, { useState, useEffect } from 'react';
import { fetchAlerts, fetchAlertSummary } from '../api';

interface Alert {
  timestamp: string;
  type: string;
  severity: string;
  source: string;
  description: string;
}

interface AlertSummary {
  total_alerts: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}

const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');

  useEffect(() => {
    const loadData = async () => {
      try {
        const [alertsData, summaryData] = await Promise.all([
          fetchAlerts(),
          fetchAlertSummary()
        ]);
        
        setAlerts(alertsData);
        setSummary(summaryData);
      } catch (error) {
        console.error('Error loading alerts data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const filteredAlerts = filterSeverity === 'all' 
    ? alerts 
    : alerts.filter(alert => alert.severity === filterSeverity);

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return <span className="px-2 py-1 bg-red-600 text-white text-xs rounded-full">High</span>;
      case 'medium':
        return <span className="px-2 py-1 bg-yellow-500 text-white text-xs rounded-full">Medium</span>;
      case 'low':
        return <span className="px-2 py-1 bg-blue-500 text-white text-xs rounded-full">Low</span>;
      default:
        return <span className="px-2 py-1 bg-gray-500 text-white text-xs rounded-full">{severity}</span>;
    }
  };

  if (loading) {
    return <div className="p-6">Loading alerts data...</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-2">Security Alerts</h1>
        <p className="text-gray-600">Monitor security incidents and alerts</p>
      </div>

      {summary && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-white p-4 rounded-md shadow">
            <div className="text-sm text-gray-500">Total Alerts</div>
            <div className="text-2xl font-bold">{summary.total_alerts}</div>
          </div>
          
          <div className="bg-white p-4 rounded-md shadow">
            <div className="text-sm text-gray-500">High Severity</div>
            <div className="text-2xl font-bold text-red-600">{summary.by_severity.high || 0}</div>
          </div>
          
          <div className="bg-white p-4 rounded-md shadow">
            <div className="text-sm text-gray-500">Medium Severity</div>
            <div className="text-2xl font-bold text-yellow-600">{summary.by_severity.medium || 0}</div>
          </div>
          
          <div className="bg-white p-4 rounded-md shadow">
            <div className="text-sm text-gray-500">Low Severity</div>
            <div className="text-2xl font-bold text-blue-600">{summary.by_severity.low || 0}</div>
          </div>
        </div>
      )}

      <div className="mb-4 flex gap-2">
        <button 
          className={`px-4 py-2 rounded-md ${filterSeverity === 'all' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilterSeverity('all')}
        >
          All Alerts
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${filterSeverity === 'high' ? 'bg-red-600 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilterSeverity('high')}
        >
          High Severity
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${filterSeverity === 'medium' ? 'bg-yellow-500 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilterSeverity('medium')}
        >
          Medium Severity
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${filterSeverity === 'low' ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilterSeverity('low')}
        >
          Low Severity
        </button>
      </div>

      <div className="bg-white rounded-md shadow">
        <div className="grid grid-cols-12 p-4 font-semibold border-b">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-2">Type</div>
          <div className="col-span-2">Source</div>
          <div className="col-span-5">Description</div>
          <div className="col-span-1">Severity</div>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="p-4 text-center text-gray-500">No alerts found</div>
        ) : (
          filteredAlerts.map((alert, index) => (
            <div 
              key={index} 
              className="grid grid-cols-12 p-4 hover:bg-gray-50 border-b"
            >
              <div className="col-span-2">{new Date(alert.timestamp).toLocaleString()}</div>
              <div className="col-span-2">{alert.type}</div>
              <div className="col-span-2">{alert.source}</div>
              <div className="col-span-5">{alert.description}</div>
              <div className="col-span-1">{getSeverityBadge(alert.severity)}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Alerts;