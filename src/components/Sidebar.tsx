import { Activity, Eye, Home, Network, ScanSearch, Settings, ShieldAlert, Users } from "lucide-react";
import type { ViewId } from "../types";

const items: Array<[ViewId, string, typeof Home]> = [
  ["overview", "Overview", Home], ["scans", "Scans", ScanSearch], ["threats", "Threats", ShieldAlert],
  ["privacy", "Privacy", Eye], ["network", "Network", Network], ["members", "Members", Users], ["diagnostics", "Diagnostics", Activity]
];

export function Sidebar({ view, onChange }: { view: ViewId; onChange: (view: ViewId) => void }) {
  return <aside className="sidebar">
    <div className="brand"><span className="brand-mark"><ShieldAlert size={22} /></span><span><strong>Sentinel</strong> Local<small>Local security, total control.</small></span></div>
    <nav aria-label="Primary navigation">{items.map(([id, label, Icon]) => <button key={id} aria-label={label} className={view === id ? "nav-item active" : "nav-item"} onClick={() => onChange(id)} aria-current={view === id ? "page" : undefined}><Icon size={20} /><span>{label}</span></button>)}</nav>
    <button aria-label="Settings" className={view === "settings" ? "nav-item active settings-link" : "nav-item settings-link"} onClick={() => onChange("settings")}><Settings size={20} /><span>Settings</span></button>
    <div className="sidebar-status"><span className="status-dot good" /> <strong>Protected</strong><small><span className="status-dot review" /> 1 item needs review</small></div>
    <footer>Version 0.1.0 · Prototype<br/><span>▣ Local only</span></footer>
  </aside>;
}
