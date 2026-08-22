import { Bell, LockKeyhole, Radar, Wifi } from "lucide-react";

export function Header({ title, subtitle, networkName, scanning, onScan }: { title: string; subtitle: string; networkName: string; scanning: boolean; onScan: () => void }) {
  return <header className="topbar">
    <div><h1>{title}</h1><p>{subtitle}</p></div>
    <div className="header-actions">
      <div className="header-fact"><LockKeyhole size={18}/><span><strong>Local only</strong><small>Your data stays on this PC</small></span></div>
      <div className="header-fact"><Wifi size={18}/><span><strong>Network: {networkName}</strong><small>Private network</small></span></div>
      <button className="icon-button" aria-label="Notifications"><Bell size={20}/><span className="notification-dot" /></button>
      <button className="primary-button" onClick={onScan} disabled={scanning}><Radar size={19}/>{scanning ? "Scanning…" : "Run smart scan"}</button>
    </div>
  </header>;
}
