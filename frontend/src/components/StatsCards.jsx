import React from 'react';

function StatsCards({ stats, alertCount }) {
  const cards = [
    {
      label: 'Total Packets',
      value: stats?.total_packets?.toLocaleString() || '0',
      color: '#3b82f6',
    },
    {
      label: 'Normal Traffic',
      value: stats?.normal_count?.toLocaleString() || '0',
      color: '#22c55e',
    },
    {
      label: 'Attacks Detected',
      value: stats?.attack_count?.toLocaleString() || '0',
      color: '#ef4444',
    },
    {
      label: 'DoS Attacks',
      value: stats?.dos_count?.toLocaleString() || '0',
      color: '#f97316',
    },
    {
      label: 'Probe Attacks',
      value: stats?.probe_count?.toLocaleString() || '0',
      color: '#a855f7',
    },
    {
      label: 'R2L Attacks',
      value: stats?.r2l_count?.toLocaleString() || '0',
      color: '#eab308',
    },
    {
      label: 'U2R Attacks',
      value: stats?.u2r_count?.toLocaleString() || '0',
      color: '#ec4899',
    },
    {
      label: 'Total Alerts',
      value: alertCount.toLocaleString(),
      color: '#6366f1',
    },
  ];

  return (
    <div className="stats-grid">
      {cards.map((card) => (
        <div key={card.label} className="stat-card" style={{ borderTopColor: card.color }}>
          <span className="stat-value" style={{ color: card.color }}>
            {card.value}
          </span>
          <span className="stat-label">{card.label}</span>
        </div>
      ))}
    </div>
  );
}

export default StatsCards;
