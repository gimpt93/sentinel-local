import { AlertTriangle, Ban, CheckCircle2, RefreshCw, ShieldCheck } from "lucide-react";
import type { ActivityEvent } from "../types";

export function EventTimeline({ events }: { events: ActivityEvent[] }) {
  const icons = { device: AlertTriangle, scan: CheckCircle2, blocked: Ban, update: RefreshCw, vpn: ShieldCheck };
  return <section className={`event-timeline ${events.length === 0 ? "empty-events" : ""}`}><h2>Recent events</h2>{events.length === 0 && <p>No local security events recorded yet.</p>}{events.slice(0,5).map(event => { const Icon = icons[event.type]; return <article key={event.id}><Icon className={event.type === "device" ? "review" : event.type === "blocked" ? "risk" : "good"} size={20}/><span><time>{event.time}</time><strong>{event.title}</strong><small>{event.detail}</small></span></article>; })}</section>;
}
