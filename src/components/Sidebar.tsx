import { Activity, Eye, Home, Network, ScanSearch, Settings, ShieldAlert, Users } from "lucide-react";
import type { ViewId } from "../types";

const items: Array<[ViewId, string, typeof Home]> = [
  ["overview", "Overview", Home], ["scans", "Scans", ScanSearch], ["threats", "Threats", ShieldAlert],
  ["privacy", "Privacy", Eye], ["network", "Network", Network], ["members", "Members", Users], ["diagnostics", "Diagnostics", Activity]
];

export function Sidebar({ view, overall, reviewCount, onChange }: { view: ViewId; overall: string; reviewCount: number; onChange: (view: ViewId) => void }) {
  return <aside className="sidebar">
    <div className="brand"><span className="brand-mark"><ShieldAlert size={22} /></span><span><strong>Sentinel</strong> Local<small>Local security, total control.</small></span></div>
    <nav aria-label="Primary navigation">{items.map(([id, label, Icon]) => <button key={id} aria-label={label} className={view === id ? "nav-item active" : "nav-item"} onClick={() => onChange(id)} aria-current={view === id ? "page" : undefined}><Icon size={20} /><span>{label}</span></button>)}</nav>
    <button aria-label="Settings" className={view === "settings" ? "nav-item active settings-link" : "nav-item settings-link"} onClick={() => onChange("settings")}><Settings size={20} /><span>Settings</span></button>
    <div className="sidebar-status"><span className={`status-dot ${overall === "at_risk" ? "risk" : overall === "protected" ? "good" : "review"}`} /> <strong>{overall === "at_risk" ? "At risk" : overall === "protected" ? "Protected" : "Needs review"}</strong><small><span className={`status-dot ${reviewCount ? "review" : "good"}`} /> {reviewCount ? `${reviewCount} unknown ${reviewCount === 1 ? "device" : "devices"}` : "No unknown devices"}</small></div>
    <footer>Version 0.2.0 · Safe release<br/><span>▣ Local only</span></footer>
  </aside>;
}
