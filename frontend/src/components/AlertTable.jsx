import React from 'react';

function AlertTable({ alerts, loading }) {
  if (loading) {
    return <div className="loading">Loading alerts...</div>;
  }

  if (alerts.length === 0) {
    return (
      <div className="empty-state">
        <p>No alerts detected yet.</p>
        <p className="empty-hint">Alerts will appear here in real-time when the capture system detects attacks.</p>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table className="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Category</th>
            <th>Attack Type</th>
            <th>Confidence</th>
            <th>Severity</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Port</th>
            <th>Protocol</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className={`severity-${alert.severity}`}>
              <td className="time-cell">{formatTime(alert.timestamp)}</td>
              <td>
                <span className={`category-badge cat-${alert.category?.toLowerCase()}`}>
                  {alert.category}
                </span>
              </td>
              <td>{alert.attack_type}</td>
              <td>
                <div className="confidence-bar">
                  <div
                    className="confidence-fill"
                    style={{
                      width: `${alert.confidence}%`,
                      backgroundColor: getConfidenceColor(alert.confidence),
                    }}
                  />
                  <span>{alert.confidence}%</span>
                </div>
              </td>
              <td>
                <span className={`severity-badge sev-${alert.severity}`}>
                  {alert.severity}
                </span>
              </td>
              <td className="mono">{alert.src_ip}</td>
              <td className="mono">{alert.dst_ip}</td>
              <td className="mono">{alert.dst_port}</td>
              <td>{alert.protocol?.toUpperCase()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatTime(timestamp) {
  if (!timestamp) return '-';
  const date = new Date(timestamp);
  return date.toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function getConfidenceColor(confidence) {
  if (confidence > 80) return '#ef4444';
  if (confidence > 50) return '#f97316';
  return '#eab308';
}

export default AlertTable;
