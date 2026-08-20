import React, { useEffect, useState } from 'react';
import { Shield, Activity } from 'lucide-react';
import LiveFlow from './components/LiveFlow';
import AuditLedger from './components/AuditLedger';
import Metrics from './components/Metrics';
import PolicyMatrix from './components/PolicyMatrix';

export type AuditLog = {
  id: number;
  timestamp: string;
  entity_type: string;
  action: string;
  score: number;
  current_hash: string;
  prev_hash: string;
};

export type InterceptEvent = {
  type: string;
  session_id: string;
  original_length: number;
  detections: any[];
  latency_ms: number;
  audit_logs: AuditLog[];
  masked_prompt: string;
};

function App() {
  const [events, setEvents] = useState<InterceptEvent[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [throughput, setThroughput] = useState(0);
  const [p95Latency, setP95Latency] = useState(0);

  useEffect(() => {
    const ws = new WebSocket('ws://127.0.0.1:8000/ws');
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'INTERCEPT') {
        setEvents(prev => [...prev.slice(-49), data]);
        if (data.audit_logs && data.audit_logs.length > 0) {
          setLogs(prev => [...data.audit_logs, ...prev].slice(0, 100));
        }
      }
    };

    const interval = setInterval(() => {
      setEvents(prev => {
        const recent = prev.filter(e => Date.now() - new Date(e.audit_logs[0]?.timestamp || Date.now()).getTime() < 10000);
        setThroughput(Math.round(recent.length / 10)); // proxy for req/sec over 10s
        if (recent.length > 0) {
          const lats = recent.map(e => e.latency_ms).sort((a,b) => a - b);
          setP95Latency(Math.round(lats[Math.floor(lats.length * 0.95)]));
        }
        return prev;
      });
    }, 1000);

    return () => {
      ws.close();
      clearInterval(interval);
    };
  }, []);

  return (
    <>
      <div className="command-bar">
        <div className="logo">
          <Shield size={24} className="safe" />
          AI DATA FIREWALL // SOC
        </div>
        <div className="command-stats">
          <div className="stat-item">
            <span className="label">System Status</span>
            <span className="value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div className="status-pulse"></div> ACTIVE
            </span>
          </div>
          <div className="stat-item">
            <span className="label">Throughput</span>
            <span className="value">{throughput} req/s</span>
          </div>
          <div className="stat-item">
            <span className="label">p95 Latency</span>
            <span className="value">{p95Latency} ms</span>
          </div>
        </div>
      </div>
      
      <div className="layout-grid">
        <div className="panel panel-flow">
          <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Live Interception Flow</span>
            <Activity size={16} />
          </div>
          <LiveFlow events={events} />
        </div>
        
        <div className="panel panel-radar">
          <div className="panel-title">Policy Matrix</div>
          <PolicyMatrix />
        </div>
        
        <div className="panel panel-metrics">
          <div className="panel-title">Metrics & Telemetry</div>
          <Metrics events={events} />
        </div>
        
        <div className="panel panel-ledger">
          <div className="panel-title">Audit Ledger</div>
          <AuditLedger logs={logs} />
        </div>
      </div>
    </>
  );
}

export default App;
