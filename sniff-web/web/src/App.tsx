import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router';
import { useState, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { getToken, setToken } from './hooks/useApi';
import Dashboard from './pages/Dashboard';
import Capture from './pages/Capture';
import Services from './pages/Services';
import Credentials from './pages/Credentials';
import PcapFiles from './pages/PcapFiles';
import ClickHousePage from './pages/ClickHouse';
import KafkaPage from './pages/Kafka';
import Config from './pages/Config';

export default function App() {
  const [token, setTok] = useState<string | null>(getToken());

  const logout = useCallback(() => {
    setToken(null);
    setTok(null);
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login onLogin={(t) => { setToken(t); setTok(t); }} />} />
        <Route
          path="/*"
          element={
            token ? <AuthenticatedLayout onLogout={logout} /> : <Navigate to="/login" />
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

function Login({ onLogin }: { onLogin: (t: string) => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setError(body.detail || `Login failed: ${r.status}`);
        return;
      }
      const body = await r.json();
      setToken(body.token);
      onLogin(body.token);
      navigate('/dashboard');
    } catch (e: any) {
      setError(`Network error: ${e.message}`);
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <h1>SNIFF Web GUI</h1>
        {error && <div className="error">{error}</div>}
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" className="btn" style={{ width: '100%' }}>Sign in</button>
      </form>
    </div>
  );
}

function AuthenticatedLayout({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="app-layout">
      <TopBar user="admin" onLogout={onLogout} />
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/capture" element={<Capture />} />
          <Route path="/services" element={<Services />} />
          <Route path="/credentials" element={<Credentials />} />
          <Route path="/pcap" element={<PcapFiles />} />
          <Route path="/clickhouse" element={<ClickHousePage />} />
          <Route path="/kafka" element={<KafkaPage />} />
          <Route path="/config" element={<Config />} />
        </Routes>
      </main>
    </div>
  );
}