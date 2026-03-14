import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const COLORS = {
  DoS: '#f85149',
  Probe: '#f0883e',
  R2L: '#d29922',
  U2R: '#a371f7',
  Normal: '#3fb950',
};

function AttackChart({ alerts }) {
  const categoryData = useMemo(() => {
    const counts = {};
    alerts.forEach((a) => {
      counts[a.category] = (counts[a.category] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [alerts]);

  const total = useMemo(() => categoryData.reduce((s, d) => s + d.value, 0), [categoryData]);

  if (alerts.length === 0) {
    return (
      <div className="card">
        <h3>Attack Distribution</h3>
        <div className="empty-chart">No data yet</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Attack Distribution</h3>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={categoryData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={95}
            dataKey="value"
            stroke="none"
          >
            {categoryData.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] || '#58a6ff'} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: '#1a1f2e',
              border: '1px solid #30363d',
              borderRadius: 6,
              color: '#e6edf3',
            }}
            formatter={(value, name) => [`${value} alerts`, name]}
          />
          <text x="50%" y="46%" textAnchor="middle" className="donut-center-value">{total}</text>
          <text x="50%" y="56%" textAnchor="middle" className="donut-center-label">Total</text>
        </PieChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {categoryData.map((entry) => (
          <div key={entry.name} className="legend-item">
            <span className="legend-dot" style={{ backgroundColor: COLORS[entry.name] || '#58a6ff' }} />
            <span>{entry.name}</span>
            <span className="legend-value">{entry.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default AttackChart;
