import React, { useMemo, useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const CATEGORY_COLORS = {
  DoS: '#f85149',
  Probe: '#f0883e',
  R2L: '#d29922',
  U2R: '#a371f7',
};

function ThreatTrends({ alerts }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 10000);
    return () => clearInterval(interval);
  }, []);

  const trendData = useMemo(() => {
    const now = Date.now();
    const intervalMs = 60 * 1000;
    const slots = 10;

    const buckets = [];
    for (let i = slots - 1; i >= 0; i--) {
      const slotStart = now - (i + 1) * intervalMs;
      const slotEnd = now - i * intervalMs;

      const slotAlerts = alerts.filter((a) => {
        const t = new Date(a.timestamp).getTime();
        return t >= slotStart && t < slotEnd;
      });

      const label = new Date(slotEnd).toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
      });

      const bucket = { time: label };
      let total = 0;
      Object.keys(CATEGORY_COLORS).forEach((cat) => {
        const count = slotAlerts.filter((a) => a.category === cat).length;
        bucket[cat] = count;
        total += count;
      });
      bucket.Total = total;

      buckets.push(bucket);
    }

    return buckets;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts, tick]);

  const activeCategories = useMemo(() => {
    const cats = new Set();
    alerts.forEach((a) => {
      if (CATEGORY_COLORS[a.category]) cats.add(a.category);
    });
    return Array.from(cats);
  }, [alerts]);

  if (alerts.length === 0) {
    return (
      <div className="card">
        <h3>Threat Trends Over Time</h3>
        <div className="empty-chart">No data yet</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Threat Trends Over Time</h3>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={trendData}>
          <defs>
            {Object.entries(CATEGORY_COLORS).map(([name, color]) => (
              <linearGradient key={name} id={`grad-${name}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.3} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#8b949e', fontSize: 11 }}
            axisLine={{ stroke: '#21262d' }}
            tickLine={{ stroke: '#21262d' }}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: '#8b949e', fontSize: 11 }}
            axisLine={{ stroke: '#21262d' }}
            tickLine={{ stroke: '#21262d' }}
          />
          <Tooltip
            contentStyle={{
              background: '#1a1f2e',
              border: '1px solid #30363d',
              borderRadius: 6,
              color: '#e6edf3',
            }}
          />
          {activeCategories.map((cat) => (
            <Area
              key={cat}
              type="monotone"
              dataKey={cat}
              stroke={CATEGORY_COLORS[cat]}
              strokeWidth={2}
              fill={`url(#grad-${cat})`}
              dot={{ r: 3, fill: CATEGORY_COLORS[cat] }}
              activeDot={{ r: 5 }}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {Object.entries(CATEGORY_COLORS).map(([name, color]) => (
          <div key={name} className="legend-item">
            <span className="legend-dot" style={{ backgroundColor: color }} />
            <span>{name}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default ThreatTrends;
