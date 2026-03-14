import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const SEVERITY_COLORS = {
  Critical: '#f85149',
  High: '#f0883e',
  Medium: '#d29922',
  Low: '#3fb950',
};

function SeverityChart({ alerts }) {
  const severityData = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    alerts.forEach((a) => {
      if (a.severity === 'high' && a.confidence > 90) {
        counts.Critical++;
      } else if (a.severity === 'high') {
        counts.High++;
      } else if (a.severity === 'medium') {
        counts.Medium++;
      } else if (a.severity === 'low') {
        counts.Low++;
      }
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .filter((d) => d.value > 0);
  }, [alerts]);

  const total = useMemo(() => severityData.reduce((s, d) => s + d.value, 0), [severityData]);

  if (alerts.length === 0) {
    return (
      <div className="card">
        <h3>Threat Distribution by Severity</h3>
        <div className="empty-chart">No data yet</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Threat Distribution by Severity</h3>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={severityData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={95}
            dataKey="value"
            stroke="none"
          >
            {severityData.map((entry) => (
              <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: '#1a1f2e',
              border: '1px solid #30363d',
              borderRadius: 6,
              color: '#e6edf3',
            }}
            formatter={(value, name) => [`${value} threats`, name]}
          />
          <text x="50%" y="46%" textAnchor="middle" className="donut-center-value">{total}</text>
          <text x="50%" y="56%" textAnchor="middle" className="donut-center-label">Threats</text>
        </PieChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {Object.entries(SEVERITY_COLORS).map(([name, color]) => {
          const entry = severityData.find((d) => d.name === name);
          return (
            <div key={name} className="legend-item">
              <span className="legend-dot" style={{ backgroundColor: color }} />
              <span>{name}</span>
              <span className="legend-value">{entry?.value || 0}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default SeverityChart;
