import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import Analytics from './pages/Analytics';
import UserActivity from './pages/UserActivity';
import SystemLogs from './pages/SystemLogs';
import Alerts from './pages/Alerts';

const App: React.FC = () => {
  return (
    <Router>
      <div className="flex h-screen bg-gray-200">
        <Sidebar />
        <div className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/user-activity" element={<UserActivity />} />
            <Route path="/system-logs" element={<SystemLogs />} />
            <Route path="/alerts" element={<Alerts />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
};

export default App;