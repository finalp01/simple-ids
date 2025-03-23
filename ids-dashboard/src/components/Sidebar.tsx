import React from 'react';
import { NavLink } from 'react-router-dom';

const Sidebar: React.FC = () => {
  return (
    <div className="w-80 h-full bg-gray-300 p-6">
      <h1 className="text-2xl font-bold mb-8">IDS Dashboard</h1>
      <nav className="flex flex-col space-y-4">
        <NavLink 
          to="/" 
          className={({ isActive }) => 
            `text-xl hover:text-gray-900 ${isActive ? 'font-bold' : 'font-normal'}`
          }
        >
          Overview
        </NavLink>
        <NavLink 
          to="/analytics" 
          className={({ isActive }) => 
            `text-xl hover:text-gray-900 ${isActive ? 'font-bold' : 'font-normal'}`
          }
        >
          Analytics
        </NavLink>
        <NavLink 
          to="/user-activity" 
          className={({ isActive }) => 
            `text-xl hover:text-gray-900 ${isActive ? 'font-bold' : 'font-normal'}`
          }
        >
          User activity
        </NavLink>
        <NavLink 
          to="/system-logs" 
          className={({ isActive }) => 
            `text-xl hover:text-gray-900 ${isActive ? 'font-bold' : 'font-normal'}`
          }
        >
          System logs
        </NavLink>
        <NavLink 
          to="/alerts" 
          className={({ isActive }) => 
            `text-xl hover:text-gray-900 ${isActive ? 'font-bold' : 'font-normal'}`
          }
        >
          Alerts
        </NavLink>
      </nav>
    </div>
  );
};

export default Sidebar;