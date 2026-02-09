import React, { useState, useEffect } from 'react';
import { supabase } from './lib/supabase';
import StatsCards from './components/StatsCards';
import AlertTable from './components/AlertTable';
import AttackChart from './components/AttackChart';
import RecentActivity from './components/RecentActivity';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ category: '', severity: '' });
  const [connected, setConnected] = useState(false);

  // Fetch initial data
  useEffect(() => {
    fetchAlerts();
    fetchStats();
  }, [filter]);

  // Subscribe to realtime alerts
  useEffect(() => {
    const channel = supabase
      .channel('alerts-realtime')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'alerts' },
        (payload) => {
          const newAlert = payload.new;
          // Only add to list if it matches the active filter
          setAlerts((prev) => {
            const matchesCategory = !filter.category || newAlert.category === filter.category;
            const matchesSeverity = !filter.severity || newAlert.severity === filter.severity;
            if (matchesCategory && matchesSeverity) {
              return [newAlert, ...prev];
            }
            return prev;
          });
          // Refresh stats when new alert arrives
          fetchStats();
        }
      )
      .subscribe((status) => {
        setConnected(status === 'SUBSCRIBED');
      });

    return () => {
      supabase.removeChannel(channel);
    };
  }, [filter]);

  async function fetchAlerts() {
    let query = supabase
      .from('alerts')
      .select('*', { count: 'exact' })
      .order('timestamp', { ascending: false })
      .limit(100);

    if (filter.category) query = query.eq('category', filter.category);
    if (filter.severity) query = query.eq('severity', filter.severity);

    const { data, count } = await query;
    setAlerts(data || []);
    setLoading(false);
  }

  async function fetchStats() {
    const { data } = await supabase
      .from('traffic_stats')
      .select('*')
      .limit(1)
      .single();

    setStats(data);
  }

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <h1>NIDS Dashboard</h1>
          <p>Network Intrusion Detection System</p>
        </div>
        <div className="header-right">
          <span className={`status-badge ${connected ? 'connected' : 'disconnected'}`}>
            {connected ? 'Live' : 'Connecting...'}
          </span>
        </div>
      </header>

      <main className="main">
        <StatsCards stats={stats} alertCount={alerts.length} />

        <div className="charts-section">
          <AttackChart alerts={alerts} />
          <RecentActivity alerts={alerts.slice(0, 5)} />
        </div>

        <div className="table-section">
          <div className="table-header">
            <h2>Alert Log</h2>
            <div className="filters">
              <select
                value={filter.category}
                onChange={(e) => setFilter((f) => ({ ...f, category: e.target.value }))}
              >
                <option value="">All Categories</option>
                <option value="DoS">DoS</option>
                <option value="Probe">Probe</option>
                <option value="R2L">R2L</option>
                <option value="U2R">U2R</option>
              </select>
              <select
                value={filter.severity}
                onChange={(e) => setFilter((f) => ({ ...f, severity: e.target.value }))}
              >
                <option value="">All Severities</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <AlertTable alerts={alerts} loading={loading} />
        </div>
      </main>

      <footer className="footer">
        <p>University of Botswana - Final Year Project | Supervisor: Dr T Mapoka</p>
      </footer>
    </div>
  );
}

export default App;
