import React from 'react';

interface ThreatSummaryProps {
  totalAlerts: number;
  alertsLastHour: number;
  alertsLastDay: number;
  severityCounts: {
    high: number;
    medium: number;
    low: number;
  };
  topThreats: Array<{ type: string; count: number }>;
}

const ThreatSummary: React.FC<ThreatSummaryProps> = ({ 
  totalAlerts, 
  alertsLastHour, 
  alertsLastDay, 
  severityCounts,
  topThreats
}) => {
  return (
    <div className="flex flex-col items-center">
      <h2 className="text-6xl font-bold">{totalAlerts}</h2>
      <div className="flex gap-2 mt-2">
        {topThreats.slice(0, 2).map((threat, index) => (
          <span key={index} className="bg-red-600 text-white px-3 py-1 rounded-full">
            {threat.type}
          </span>
        ))}
      </div>
    </div>
  );
};

export default ThreatSummary;