import React from 'react';

function RecentActivity({ alerts }) {
  if (alerts.length === 0) {
    return (
      <div className="activity-card">
        <h3>Recent Activity</h3>
        <div className="empty-chart">Waiting for alerts...</div>
      </div>
    );
  }

  return (
    <div className="activity-card">
      <h3>Recent Activity</h3>
      <ul className="activity-list">
        {alerts.map((alert) => (
          <li key={alert.id} className="activity-item">
            <div className={`activity-dot sev-${alert.severity}`} />
            <div className="activity-content">
              <div className="activity-title">
                <span className={`category-badge cat-${alert.category?.toLowerCase()}`}>
                  {alert.category}
                </span>
                <span className="activity-type">{alert.attack_type}</span>
              </div>
              <div className="activity-meta">
                <span className="mono">{alert.src_ip}</span>
                <span className="arrow">&rarr;</span>
                <span className="mono">{alert.dst_ip}:{alert.dst_port}</span>
                <span className="activity-confidence">{alert.confidence}%</span>
              </div>
              <div className="activity-time">{formatTimeAgo(alert.timestamp)}</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function formatTimeAgo(timestamp) {
  if (!timestamp) return '';
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default RecentActivity;
