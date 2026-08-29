import React from 'react';
import type { AuditLog } from '../App';

export default function AuditLedger({ logs }: { logs: AuditLog[] }) {
  const verifyChain = async () => {
    try {
      const res = await fetch('http://localhost:8000/audit/verify');
      const data = await res.json();
      alert(data.valid ? '✅ Audit chain is cryptographically valid.' : '❌ Audit chain integrity compromised!');
    } catch (e) {
      alert('Error verifying chain');
    }
  };

  return (
    <div style={{ height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
        <button onClick={verifyChain} style={{ 
          background: 'transparent', 
          border: '1px solid var(--bg-panel-border)', 
          color: 'var(--text-secondary)',
          padding: '4px 8px',
          borderRadius: '4px',
          cursor: 'pointer',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.75rem'
        }}>
          Verify Chain Integrity
        </button>
      </div>
      
      {logs.map((log, i) => (
        <div key={log.id} style={{
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          paddingLeft: '16px'
        }}>
          {/* Hash chain connecting line */}
          {i !== logs.length - 1 && (
            <div style={{
              position: 'absolute',
              left: '7px',
              top: '20px',
              bottom: '-20px',
              width: '1px',
              backgroundColor: 'var(--bg-panel-border)',
              zIndex: 0
            }} />
          )}
          
          {/* Node dot */}
          <div style={{
            position: 'absolute',
            left: '4px',
            top: '8px',
            width: '7px',
            height: '7px',
            borderRadius: '50%',
            backgroundColor: log.action === 'BLOCK' ? 'var(--accent-block)' : 
                             log.action === 'MASK' ? 'var(--accent-mask)' : 'var(--accent-safe)',
            zIndex: 1
          }} />

          <div style={{ 
            fontFamily: 'var(--font-mono)', 
            fontSize: '0.75rem',
            backgroundColor: 'rgba(0,0,0,0.3)',
            padding: '8px',
            borderRadius: '4px',
            border: '1px solid var(--bg-panel-border)',
            zIndex: 1
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '4px' }}>
              <span>{new Date(log.timestamp).toISOString().split('T')[1].split('.')[0]}</span>
              <span>{log.entity_type}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ 
                color: log.action === 'BLOCK' ? 'var(--accent-block)' : 
                       log.action === 'MASK' ? 'var(--accent-mask)' : 'var(--accent-safe)'
              }}>
                [{log.action}]
              </span>
              <span style={{ color: 'var(--text-secondary)' }}>
                {log.prev_hash.substring(0, 8)} → {log.current_hash.substring(0, 8)}
              </span>
            </div>
          </div>
        </div>
      ))}
      
      {logs.length === 0 && (
        <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', textAlign: 'center', marginTop: '20px' }}>
          Waiting for events...
        </div>
      )}
    </div>
  );
}
