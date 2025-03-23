import React, { useState, useEffect } from 'react';
import { fetchLogs } from '../api';

interface LogEntry {
  timestamp: string;
  source: string;
  content: string;
}

const SystemLogs: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(3600); // Default: last hour (in seconds)
  const [filter, setFilter] = useState('');

  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await fetchLogs(timeRange);
        setLogs(data);
      } catch (error) {
        console.error('Error loading system logs:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const filteredLogs = filter
    ? logs.filter(log => 
        log.source.toLowerCase().includes(filter.toLowerCase()) || 
        log.content.toLowerCase().includes(filter.toLowerCase())
      )
    : logs;

  if (loading && logs.length === 0) {
    return <div className="p-6">Loading system logs...</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-2">System Logs</h1>
        <p className="text-gray-600">View system and application logs</p>
      </div>

      <div className="flex justify-between mb-4">
        <div className="flex gap-2">
          <button 
            className={`px-4 py-2 rounded-md ${timeRange === 3600 ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
            onClick={() => setTimeRange(3600)}
          >
            Last Hour
          </button>
          <button 
            className={`px-4 py-2 rounded-md ${timeRange === 3600 * 6 ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
            onClick={() => setTimeRange(3600 * 6)}
          >
            Last 6 Hours
          </button>
          <button 
            className={`px-4 py-2 rounded-md ${timeRange === 3600 * 24 ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
            onClick={() => setTimeRange(3600 * 24)}
          >
            Last 24 Hours
          </button>
        </div>
        
        <div>
          <input
            type="text"
            placeholder="Filter logs..."
            className="px-4 py-2 border rounded-md"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      </div>

      <div className="bg-white rounded-md shadow">
        <div className="grid grid-cols-12 p-4 font-semibold border-b">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-2">Source</div>
          <div className="col-span-8">Content</div>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="p-4 text-center text-gray-500">No logs found</div>
        ) : (
          filteredLogs.map((log, index) => (
            <div 
              key={index} 
              className="grid grid-cols-12 p-4 hover:bg-gray-50 border-b"
            >
              <div className="col-span-2">{new Date(log.timestamp).toLocaleString()}</div>
              <div className="col-span-2">{log.source}</div>
              <div className="col-span-8 font-mono text-sm break-words">{log.content}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default SystemLogs;