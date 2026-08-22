import { AlertTriangle, CheckCircle2, Flame, RefreshCw, ShieldCheck } from "lucide-react";
import type { SecuritySnapshot } from "../types";

export function StatusStrip({ snapshot }: { snapshot: SecuritySnapshot }) {
  const items = [
    [ShieldCheck, snapshot.overall === "at_risk" ? "At risk" : "Protected", snapshot.overall === "at_risk" ? "Action required" : "No active threats", snapshot.overall === "at_risk" ? "risk" : "good"],
    [AlertTriangle, "1 item needs review", "Unknown device", "review"],
    [RefreshCw, "Windows updates", snapshot.updatesCurrent ? "Up to date" : "Review updates", snapshot.updatesCurrent ? "good" : "review"],
    [Flame, "Firewall", snapshot.firewall ? "On" : "Off", snapshot.firewall ? "good" : "risk"],
    [CheckCircle2, "VPN", snapshot.vpnConnected ? "Connected" : "Not connected", snapshot.vpnConnected ? "good" : "review"]
  ] as const;
  return <section className="status-strip" aria-label="Protection status">{items.map(([Icon, title, text, tone]) => <div className="status-item" key={title}><Icon className={tone} size={25}/><span><strong>{title}</strong><small>{text}</small></span></div>)}</section>;
}
