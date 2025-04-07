import React, { useEffect, useState } from 'react';
import { fetchNetworkData } from '../api';

const NetworkFlow: React.FC = () => {
  const [networkData, setNetworkData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadNetworkData = async () => {
      try {
        const data = await fetchNetworkData(300); // Last 5 minutes
        setNetworkData(data);
      } catch (error) {
        console.error('Error loading network data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadNetworkData();
    const interval = setInterval(loadNetworkData, 10000); // Refresh every 10 seconds
    
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div>Loading network flow data...</div>;
  }

  if (networkData.length === 0) {
    return <div>No network traffic data available</div>;
  }

  // In a real implementation, you might use a library like d3.js or recharts to visualize the network flow
  return (
    <div className="h-60 flex items-center justify-center bg-gray-100 rounded">
      <p className="text-gray-500">Network flow visualization would be rendered here</p>
      {/* In a complete implementation, you would use the networkData state to render a visualization */}
    </div>
  );
};

export default NetworkFlow;