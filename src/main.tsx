import React from 'react';
import ReactDOM from 'react-dom/client';
import { PhishingDashboard } from '../UI/PhishingDashboard';
import './index.css';

const rootElement = document.getElementById('root');
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <PhishingDashboard />
    </React.StrictMode>
  );
}
