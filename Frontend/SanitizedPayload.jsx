import React from 'react';

// Escapes special characters to prevent cross-site scripting (XSS)
function sanitizeString(str) {
  return String(str ?? '').replace(/[&<>"']/g, (match) => {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    };
    return map[match];
  });
}

export default function SanitizedPayload({ rawPayload }) {
  const cleanPayload = sanitizeString(rawPayload || '');
  return (
    <pre style={{ backgroundColor: '#0f172a', color: '#e2e8f0', padding: '10px', borderRadius: '4px' }}>
      {cleanPayload}
    </pre>
  );
}
