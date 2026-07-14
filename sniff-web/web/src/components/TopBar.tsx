export function TopBar({ user, onLogout }: { user: string; onLogout: () => void }) {
  return (
    <header className="topbar">
      <span className="logo">SNIFF</span>
      <span className="grow" />
      <span className="user">{user}</span>
      <button onClick={onLogout}>Logout</button>
    </header>
  );
}