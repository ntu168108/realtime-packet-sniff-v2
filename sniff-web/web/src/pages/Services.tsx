import { useState } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { ServiceCard } from '../components/ServiceCard';
import type { ServiceStatus } from '../types';

export default function Services() {
  const [services, setServices] = useState<ServiceStatus[]>([]);

  useWebSocket<{ type: string; data: ServiceStatus[] }>(
    '/ws/services',
    (msg) => { if (msg.type === 'services') setServices(msg.data); }
  );

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Services</h1>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
        {services.map((s) => (
          <ServiceCard key={s.name} name={s.name} active={s.active} />
        ))}
      </div>
    </div>
  );
}
