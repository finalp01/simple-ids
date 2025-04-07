import React from 'react';

interface SystemMetricsProps {
  cpuUsage: number;
  memoryUsage: number;
}

const SystemMetrics: React.FC<SystemMetricsProps> = ({ cpuUsage, memoryUsage }) => {
  // Ensure values are between 0-100
  const normalizedCpu = Math.min(100, Math.max(0, cpuUsage));
  const normalizedMemory = Math.min(100, Math.max(0, memoryUsage));
  
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span>Cpu usage</span>
          <span>{Math.round(normalizedCpu)}</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2.5">
          <div 
            className="bg-black h-2.5 rounded-full" 
            style={{ width: `${normalizedCpu}%` }}
          ></div>
        </div>
      </div>
      
      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span>Memory usage</span>
          <span>{Math.round(normalizedMemory)}</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2.5">
          <div 
            className="bg-black h-2.5 rounded-full" 
            style={{ width: `${normalizedMemory}%` }}
          ></div>
        </div>
      </div>
    </div>
  );
};

export default SystemMetrics;