import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = {
  DoS: '#f97316',
  Probe: '#a855f7',
  R2L: '#eab308',
  U2R: '#ec4899',
};

function AttackChart({ alerts }) {
  // Category distribution for pie chart
  const categoryData = useMemo(() => {
    const counts = {};
    alerts.forEach((a) => {
      counts[a.category] = (counts[a.category] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [alerts]);

  // Severity distribution for bar chart
  const severityData = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      if (counts[a.severity] !== undefined) counts[a.severity]++;
    });
    return [
      { name: 'High', count: counts.high, fill: '#ef4444' },
      { name: 'Medium', count: counts.medium, fill: '#f97316' },
      { name: 'Low', count: counts.low, fill: '#eab308' },
    ];
  }, [alerts]);

  if (alerts.length === 0) {
    return (
      <div className="chart-card">
        <h3>Attack Distribution</h3>
        <div className="empty-chart">No data yet</div>
      </div>
    );
  }

  return (
    <div className="chart-card">
      <h3>Attack Distribution</h3>
      <div className="charts-row">
        <div className="chart-item">
          <h4>By Category</h4>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={categoryData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {categoryData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || '#6366f1'} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-item">
          <h4>By Severity</h4>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={severityData}>
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {severityData.map((entry, index) => (
                  <Cell key={index} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export default AttackChart;
