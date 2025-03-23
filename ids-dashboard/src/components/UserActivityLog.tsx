import React from 'react';

interface Activity {
  activity: string;
  details: string;
  severity?: 'High' | 'Medium' | 'Low';
}

interface UserActivityLogProps {
  activities: Activity[];
}

const UserActivityLog: React.FC<UserActivityLogProps> = ({ activities }) => {
  // Function to determine severity level and return appropriate styles
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'High':
        return <span className="px-2 py-1 bg-black text-white text-xs rounded-full">High</span>;
      case 'Medium':
        return <span className="px-2 py-1 bg-black text-white text-xs rounded-full">Medium</span>;
      case 'Low':
        return <span className="px-2 py-1 bg-black text-white text-xs rounded-full">Low</span>;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <div className="flex justify-between">
          <span>User login from unusual location</span>
          {getSeverityBadge('High')}
        </div>
        
        <div className="flex justify-between">
          <span>Multiple failed login attempts</span>
          {getSeverityBadge('Medium')}
        </div>
        
        <div className="flex justify-between">
          <span>Large file transfer detected</span>
          {getSeverityBadge('Low')}
        </div>
      </div>
    </div>
  );
};

export default UserActivityLog;