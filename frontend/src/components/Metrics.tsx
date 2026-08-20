import React, { useEffect, useState } from 'react';
import type { InterceptEvent } from '../App';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';

export default function Metrics({ events }: { events: InterceptEvent[] }) {
  const [chartData, setChartData] = useState<any[]>([]);

  useEffect(() => {
    // Generate a rolling window of detections over time for the sparkline
    if (events.length > 0) {
      const grouped = events.reduce((acc, curr) => {
        const time = new Date(curr.audit_logs[0]?.timestamp || Date.now()).toLocaleTimeString();
        if (!acc[time]) acc[time] = 0;
        acc[time] += curr.detections.length;
        return acc;
      }, {} as any);

      const newData = Object.keys(grouped).map(k => ({
        time: k,
        detections: grouped[k]
      })).slice(-20);

      setChartData(newData);
    }
  }, [events]);

  const totalDetections = events.reduce((sum, e) => sum + e.detections.length, 0);
  const totalEvents = events.length || 1;
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px' }}>
      
      <div style={{ display: 'flex', gap: '16px' }}>
        <div style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '4px', border: '1px solid var(--bg-panel-border)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '8px' }}>Sensitivity Rate</div>
          <div style={{ fontSize: '1.5rem', fontFamily: 'var(--font-mono)' }}>
            {Math.round((events.filter(e => e.detections.length > 0).length / totalEvents) * 100)}%
          </div>
        </div>
        <div style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '4px', border: '1px solid var(--bg-panel-border)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '8px' }}>Events Logged</div>
          <div style={{ fontSize: '1.5rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-safe)' }}>
            100%
          </div>
        </div>
      </div>

      <div style={{ flexGrow: 1, position: 'relative', marginTop: '16px' }}>
        <div style={{ position: 'absolute', top: -10, left: 0, fontSize: '0.75rem', color: 'var(--text-secondary)', zIndex: 10 }}>Detection Volume Trend</div>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorDets" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--accent-mask)" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="var(--accent-mask)" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="detections" stroke="var(--accent-mask)" fillOpacity={1} fill="url(#colorDets)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
}
