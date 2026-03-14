import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const ACCURACY_COLORS = {
  'Confirmed Threats': '#f85149',
  'False Positives': '#f0883e',
  'Blocked Automatically': '#58a6ff',
};

function AccuracyChart({ alerts, stats }) {
  const accuracyData = useMemo(() => {
    const total = alerts.length;
    if (total === 0) return [];

    const confirmed = alerts.filter((a) => a.confidence > 80).length;
    const falsePositives = alerts.filter((a) => a.confidence < 50).length;
    const blocked = total - confirmed - falsePositives;

    return [
      { name: 'Confirmed Threats', value: confirmed },
      { name: 'False Positives', value: falsePositives },
      { name: 'Blocked Automatically', value: blocked },
    ].filter((d) => d.value > 0);
  }, [alerts]);

  const accuracy = useMemo(() => {
    const total = alerts.length;
    if (total === 0) return 0;
    const confirmed = alerts.filter((a) => a.confidence > 80).length;
    const blocked = alerts.filter((a) => a.confidence >= 50 && a.confidence <= 80).length;
    return Math.round(((confirmed + blocked) / total) * 100);
  }, [alerts]);

  if (alerts.length === 0) {
    return (
      <div className="card">
        <h3>Detection Accuracy</h3>
        <div className="empty-chart">No data yet</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Detection Accuracy</h3>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={accuracyData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={95}
            dataKey="value"
            stroke="none"
          >
            {accuracyData.map((entry) => (
              <Cell key={entry.name} fill={ACCURACY_COLORS[entry.name]} />
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
          <text x="50%" y="46%" textAnchor="middle" className="donut-center-value">{accuracy}%</text>
          <text x="50%" y="56%" textAnchor="middle" className="donut-center-label">Accuracy</text>
        </PieChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {Object.entries(ACCURACY_COLORS).map(([name, color]) => {
          const entry = accuracyData.find((d) => d.name === name);
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

export default AccuracyChart;
