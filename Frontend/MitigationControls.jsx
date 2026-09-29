import React, { useState } from 'react';

export default function MitigationControls({ targetIp, onBlock }) {
  const [isAutoBlock, setIsAutoBlock] = useState(false);

  return (
    <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', padding: '20px', borderRadius: '8px' }}>
      <h3 style={{ margin: 0, color: '#f8fafc' }}>Active Defense Settings</h3>
      <div style={{ marginTop: '15px' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
          <input type="checkbox" checked={isAutoBlock} onChange={(e) => setIsAutoBlock(e.target.checked)} />
          Enable Automated Firewall Enforcement
        </label>
      </div>
      {targetIp && (
        <button onClick={() => onBlock(targetIp)} style={{ marginTop: '15px', backgroundColor: '#f43f5e', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>
          Manually Quarantined {targetIp}
        </button>
      )}
    </div>
  );
}
