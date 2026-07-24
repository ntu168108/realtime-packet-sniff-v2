import { NavLink } from 'react-router';

const ITEMS = [
  { path: '/dashboard', label: 'Dashboard' },
  { path: '/capture', label: 'Capture' },
  { path: '/services', label: 'Services' },
  { path: '/credentials', label: 'Credentials' },
  { path: '/pcap', label: 'PCAP files' },
  { path: '/kafka', label: 'Kafka' },
  { path: '/clickhouse', label: 'ClickHouse' },
  { path: '/config', label: 'Config' },
];

export function Sidebar() {
  return (
    <nav className="sidebar">
      {ITEMS.map((item) => (
        <NavLink
          key={item.path}
          to={item.path}
          className={({ isActive }) => (isActive ? 'active' : '')}
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}