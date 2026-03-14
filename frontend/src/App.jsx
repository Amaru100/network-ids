import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { supabase } from './lib/supabase';
import {
  Shield, Flame, Search, Key, UserX, CheckCircle, Trash2,
  LayoutDashboard, FileText, Filter, Activity
} from 'lucide-react';
import AlertTable from './components/AlertTable';
import AttackChart from './components/AttackChart';
import ThreatTrends from './components/ThreatTrends';
import SeverityChart from './components/SeverityChart';
import AccuracyChart from './components/AccuracyChart';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ category: '', severity: '' });
  const [connected, setConnected] = useState(false);
  const [view, setView] = useState('dashboard');

  const fetchAlerts = useCallback(async () => {
    let query = supabase
      .from('alerts')
      .select('*', { count: 'exact' })
      .order('timestamp', { ascending: false })
      .limit(5000);

    if (filter.category) query = query.eq('category', filter.category);
    if (filter.severity) query = query.eq('severity', filter.severity);

    const { data } = await query;
    setAlerts(data || []);
    setLoading(false);
  }, [filter]);

  const fetchStats = useCallback(async () => {
    const { data } = await supabase
      .from('traffic_stats')
      .select('*')
      .limit(1)
      .single();
    setStats(data);
  }, []);

  useEffect(() => {
    fetchAlerts();
    fetchStats();
  }, [fetchAlerts, fetchStats]);

  // Supabase Realtime subscription
  useEffect(() => {
    const channel = supabase
      .channel('alerts-realtime')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'alerts' },
        (payload) => {
          const newAlert = payload.new;
          setAlerts((prev) => {
            const matchesCategory = !filter.category || newAlert.category === filter.category;
            const matchesSeverity = !filter.severity || newAlert.severity === filter.severity;
            if (matchesCategory && matchesSeverity) {
              return [newAlert, ...prev];
            }
            return prev;
          });
          fetchStats();
        }
      )
      .subscribe((status) => {
        setConnected(status === 'SUBSCRIBED');
      });

    return () => {
      supabase.removeChannel(channel);
    };
  }, [filter, fetchStats]);

  const normalCount = useMemo(() => stats?.normal_count || 0, [stats]);

  const clearAlerts = async () => {
    await supabase.from('alerts').delete().neq('id', 0);
    const { data: statsRow } = await supabase.from('traffic_stats').select('id').limit(1).single();
    if (statsRow) {
      await supabase.from('traffic_stats').update({
        total_packets: 0, normal_count: 0, attack_count: 0,
        dos_count: 0, probe_count: 0, r2l_count: 0, u2r_count: 0,
      }).eq('id', statsRow.id);
    }
    setAlerts([]);
    setStats(null);
  };

  const activeFilters = (filter.category ? 1 : 0) + (filter.severity ? 1 : 0);

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Shield size={24} color="#58a6ff" />
          <span>NIDS</span>
        </div>

        <nav className="sidebar-nav">
          <div className="sidebar-section-label">Navigation</div>
          <button
            className={`sidebar-item ${view === 'dashboard' ? 'active' : ''}`}
            onClick={() => setView('dashboard')}
          >
            <LayoutDashboard size={18} />
            <span>Dashboard</span>
          </button>
          <button
            className={`sidebar-item ${view === 'alerts' ? 'active' : ''}`}
            onClick={() => setView('alerts')}
          >
            <FileText size={18} />
            <span>Alert Log</span>
            {alerts.length > 0 && <span className="sidebar-badge">{alerts.length}</span>}
          </button>
        </nav>

        <div className="sidebar-divider" />

        <div className="sidebar-filters">
          <div className="sidebar-section-label">
            <Filter size={14} />
            <span>Filters</span>
            {activeFilters > 0 && <span className="filter-count">{activeFilters}</span>}
          </div>

          <div className="sidebar-filter-group">
            <label>Category</label>
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
          </div>

          <div className="sidebar-filter-group">
            <label>Severity</label>
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

          {activeFilters > 0 && (
            <button
              className="sidebar-reset-btn"
              onClick={() => setFilter({ category: '', severity: '' })}
            >
              Reset Filters
            </button>
          )}
        </div>

        <div className="sidebar-divider" />

        <div className="sidebar-actions">
          <div className="sidebar-section-label">Actions</div>
          <button className="sidebar-clear-btn" onClick={clearAlerts}>
            <Trash2 size={16} />
            <span>Clear All Alerts</span>
          </button>
        </div>

        <div className="sidebar-footer">
          <div className="sidebar-status">
            <Activity size={14} color={connected ? '#3fb950' : '#f85149'} />
            <span>{connected ? 'System Online' : 'Disconnected'}</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="main-wrapper">
        <header className="header">
          <div className="header-left">
            <h1>Network Intrusion Detection System</h1>
          </div>
          <div className="header-right">
            <span className={`status-badge ${connected ? 'connected' : 'disconnected'}`}>
              <span className="status-dot" />
              {connected ? 'LIVE' : 'CONNECTING'}
            </span>
          </div>
        </header>

        <main className="main">
          {activeFilters > 0 && (
            <div className="filter-banner">
              <span className="filter-banner-label">Filtered by:</span>
              {filter.category && (
                <span className={`filter-tag cat-${filter.category.toLowerCase()}`}>
                  {filter.category}
                  <button onClick={() => setFilter(f => ({ ...f, category: '' }))}>×</button>
                </span>
              )}
              {filter.severity && (
                <span className={`filter-tag sev-${filter.severity}`}>
                  {filter.severity}
                  <button onClick={() => setFilter(f => ({ ...f, severity: '' }))}>×</button>
                </span>
              )}
              <button
                className="filter-clear-all"
                onClick={() => setFilter({ category: '', severity: '' })}
              >
                Clear all
              </button>
            </div>
          )}

          {view === 'dashboard' && (
            <>
              <StatsCards stats={stats} alertCount={alerts.length} normalCount={normalCount} />

              <div className="grid-row">
                <SeverityChart alerts={alerts} />
                <AccuracyChart alerts={alerts} stats={stats} />
              </div>

              <div className="grid-row">
                <AttackChart alerts={alerts} />
                <ThreatTrends alerts={alerts} />
              </div>

              <div className="card">
                <div className="card-header">
                  <h2>Recent Alerts</h2>
                </div>
                <AlertTable alerts={alerts.slice(0, 10)} loading={loading} />
              </div>
            </>
          )}

          {view === 'alerts' && (
            <div className="card">
              <div className="card-header">
                <h2>Alert Log</h2>
                <span className="alert-count-label">
                  {alerts.length >= 100 ? `${alerts.length}+` : alerts.length} alerts
                </span>
              </div>
              <AlertTable alerts={alerts} loading={loading} />
            </div>
          )}
        </main>

        <footer className="footer">
          <p>NIDS - Network Intrusion Detection System</p>
        </footer>
      </div>
    </div>
  );
}

function StatsCards({ stats, alertCount, normalCount }) {
  const cards = [
    { label: 'Total Threats', value: stats?.attack_count || alertCount || 0, icon: Shield, color: '#58a6ff' },
    { label: 'DoS Attacks', value: stats?.dos_count || 0, icon: Flame, color: '#f85149' },
    { label: 'Probe Attacks', value: stats?.probe_count || 0, icon: Search, color: '#f0883e' },
    { label: 'R2L Attacks', value: stats?.r2l_count || 0, icon: Key, color: '#d29922' },
    { label: 'U2R Attacks', value: stats?.u2r_count || 0, icon: UserX, color: '#a371f7' },
    { label: 'Normal Traffic', value: normalCount, icon: CheckCircle, color: '#3fb950' },
  ];

  return (
    <div className="stats-grid">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div key={card.label} className="stat-card">
            <div className="stat-icon" style={{ backgroundColor: `${card.color}18` }}>
              <Icon size={22} color={card.color} />
            </div>
            <div className="stat-info">
              <span className="stat-value">{card.value}</span>
              <span className="stat-label">{card.label}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default App;
