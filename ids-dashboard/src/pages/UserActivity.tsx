import React, { useState, useEffect } from 'react';
import { fetchUserActivity } from '../api';

interface UserActivityItem {
  timestamp: string;
  user: string;
  activity: string;
  details: string;
  severity?: 'high' | 'medium' | 'low';
}

const UserActivity: React.FC = () => {
  const [activities, setActivities] = useState<UserActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await fetchUserActivity();
        // Add severity for each activity based on keywords in the details
        const enhancedData = data.map(item => {
          let severity = 'low';
          const details = item.details.toLowerCase();
          
          if (details.includes('unusual') || details.includes('suspicious') || details.includes('unauthorized')) {
            severity = 'high';
          } else if (details.includes('failed') || details.includes('multiple')) {
            severity = 'medium';
          }
          
          return { ...item, severity };
        });
        
        setActivities(enhancedData);
      } catch (error) {
        console.error('Error loading user activity data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const filteredActivities = filter === 'all' 
    ? activities 
    : activities.filter(item => item.severity === filter);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'high':
        return <span className="px-2 py-1 bg-black text-white text-xs rounded-full">High</span>;
      case 'medium':
        return <span className="px-2 py-1 bg-black text-white text-xs rounded-full">Medium</span>;
      case 'low':
        return <span className="px-2 py-1 bg-black text-white text-xs rounded-full">Low</span>;
      default:
        return null;
    }
  };

  if (loading) {
    return <div className="p-6">Loading user activity data...</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-2">User Activity</h1>
        <p className="text-gray-600">Monitor user login, authentication, and system activities</p>
      </div>

      <div className="mb-4 flex gap-2">
        <button 
          className={`px-4 py-2 rounded-md ${filter === 'all' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilter('all')}
        >
          All
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${filter === 'high' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilter('high')}
        >
          High Priority
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${filter === 'medium' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilter('medium')}
        >
          Medium Priority
        </button>
        <button 
          className={`px-4 py-2 rounded-md ${filter === 'low' ? 'bg-gray-800 text-white' : 'bg-gray-200'}`}
          onClick={() => setFilter('low')}
        >
          Low Priority
        </button>
      </div>

      <div className="bg-white rounded-md shadow">
        <div className="grid grid-cols-12 p-4 font-semibold border-b">
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-2">User</div>
          <div className="col-span-2">Activity</div>
          <div className="col-span-5">Details</div>
          <div className="col-span-1">Severity</div>
        </div>

        {filteredActivities.length === 0 ? (
          <div className="p-4 text-center text-gray-500">No user activities found</div>
        ) : (
          filteredActivities.map((item, index) => (
            <div 
              key={index} 
              className="grid grid-cols-12 p-4 hover:bg-gray-50 border-b"
            >
              <div className="col-span-2">{new Date(item.timestamp).toLocaleString()}</div>
              <div className="col-span-2">{item.user}</div>
              <div className="col-span-2">{item.activity}</div>
              <div className="col-span-5">{item.details}</div>
              <div className="col-span-1">{getSeverityBadge(item.severity || 'low')}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default UserActivity;