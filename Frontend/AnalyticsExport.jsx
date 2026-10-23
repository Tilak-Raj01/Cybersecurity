import React from 'react';

export default function AnalyticsExport({ onExportCSV }) {
  return (
    <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', padding: '20px', borderRadius: '8px' }}>
      <h3 style={{ marginTop: 0, color: '#f8fafc' }}>Export Security Reports</h3>
      <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Download historical forensic log records for compliance audit requirements.</p>
      <div style={{ display: 'flex', gap: '10px' }}>
        <button type="button" onClick={() => onExportCSV('csv')} style={{ backgroundColor: '#38bdf8', border: 'none', padding: '8px 16px', borderRadius: '4px', fontWeight: 'bold', cursor: 'pointer' }}>Export CSV</button>
        <button type="button" onClick={() => onExportCSV('json')} style={{ backgroundColor: '#334155', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>Export JSON</button>
      </div>
    </div>
  );
}
