import React, { useEffect, useState } from 'react';

type Policy = {
  entity_type: string;
  action: string;
};

export default function PolicyMatrix() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  
  const fetchPolicies = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/policies');
      if (res.ok) {
        const data = await res.json();
        if (data.length === 0) {
           setPolicies([
             { entity_type: 'SSN', action: 'BLOCK' },
             { entity_type: 'CREDIT_CARD', action: 'MASK' },
             { entity_type: 'EMAIL_ADDRESS', action: 'MASK' },
             { entity_type: 'PHONE_NUMBER', action: 'MASK' }
           ]);
        } else {
           setPolicies(data);
        }
      }
    } catch (e) {
      console.error("Could not fetch policies");
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const updatePolicy = async (entity_type: string, action: string) => {
    try {
      await fetch('http://127.0.0.1:8000/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entity_type, action })
      });
      fetchPolicies();
    } catch (e) {
      console.error(e);
    }
  };

  const getStyle = (currentAction: string, targetAction: string) => {
    const isActive = currentAction === targetAction;
    let color = 'var(--text-secondary)';
    if (isActive) {
      if (targetAction === 'ALLOW') color = 'var(--accent-safe)';
      if (targetAction === 'MASK') color = 'var(--accent-mask)';
      if (targetAction === 'BLOCK') color = 'var(--accent-block)';
    }
    
    return {
      flex: 1,
      padding: '4px 0',
      textAlign: 'center' as const,
      cursor: 'pointer',
      fontSize: '0.7rem',
      fontFamily: 'var(--font-mono)',
      color: isActive ? '#000' : color,
      backgroundColor: isActive ? color : 'transparent',
      border: `1px solid ${isActive ? color : 'var(--bg-panel-border)'}`,
      transition: 'all 0.2s ease',
      fontWeight: isActive ? 700 : 400
    };
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', overflowY: 'auto', height: '100%' }}>
      {policies.map(p => (
        <div key={p.entity_type} style={{
          display: 'flex',
          flexDirection: 'column',
          backgroundColor: 'rgba(0,0,0,0.3)',
          padding: '8px',
          borderRadius: '4px',
          border: '1px solid var(--bg-panel-border)'
        }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', marginBottom: '8px' }}>
            {p.entity_type}
          </div>
          <div style={{ display: 'flex', gap: '4px' }}>
            <div style={getStyle(p.action, 'ALLOW')} onClick={() => updatePolicy(p.entity_type, 'ALLOW')}>ALLOW</div>
            <div style={getStyle(p.action, 'MASK')} onClick={() => updatePolicy(p.entity_type, 'MASK')}>MASK</div>
            <div style={getStyle(p.action, 'BLOCK')} onClick={() => updatePolicy(p.entity_type, 'BLOCK')}>BLOCK</div>
          </div>
        </div>
      ))}
    </div>
  );
}
