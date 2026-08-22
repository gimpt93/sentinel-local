import { useState } from "react";
import { AlertTriangle, ChevronDown, ChevronUp, ExternalLink, Search, ShieldCheck, X } from "lucide-react";
import type { DeviceProfile } from "../types";

export function DeviceInspector({ device, onClose, onIdentify, onRestrict, onRouter }: { device?: DeviceProfile; onClose: () => void; onIdentify: () => void; onRestrict: () => void; onRouter: () => void }) {
  const [expanded, setExpanded] = useState(false);
  if (!device) return <aside className="inspector empty-inspector"><ShieldCheck size={36}/><h2>Select a device</h2><p>Choose a node on the security map to review its local observations.</p></aside>;
  return <aside className="inspector" aria-label={`${device.name} details`}>
    <button className="inspector-close" onClick={onClose} aria-label="Close inspector"><X size={20}/></button>
    <div className="inspector-title"><AlertTriangle className={device.trust === "unknown" ? "review" : "good"}/><div><h2>{device.name}</h2><p>{device.ip}</p></div></div>
    <span className={`badge ${device.trust === "unknown" ? "review-badge" : "good-badge"}`}>{device.trust === "unknown" ? "Needs review" : "Trusted device"}</span>
    <dl className="detail-list"><div><dt>First seen</dt><dd>{device.firstSeen}</dd></div><div><dt>Last seen</dt><dd>{device.lastSeen}</dd></div><div><dt>IP address</dt><dd>{device.ip}</dd></div><div><dt>MAC address</dt><dd>{device.mac}</dd></div><div><dt>Vendor (observed)</dt><dd>{device.vendor ?? "Not identified"}</dd></div><div><dt>Discovery</dt><dd>{device.discoverySource}</dd></div></dl>
    <button className="expand-details" aria-expanded={expanded} onClick={() => setExpanded(value => !value)}>{expanded ? <ChevronUp size={16}/> : <ChevronDown size={16}/>} {expanded ? "Hide extended details" : "Expand more details"}</button>
    {expanded ? <section className="extended-details"><h3>Extended device details</h3><dl className="detail-list"><div><dt>Device type</dt><dd>{device.type}</dd></div><div><dt>Trust state</dt><dd>{device.trust}</dd></div><div><dt>Network access</dt><dd>{device.access}</dd></div><div><dt>Stable local ID</dt><dd className="break-value">{device.id}</dd></div><div><dt>Risk indicators</dt><dd>{device.riskReasons.length ? device.riskReasons.join("; ") : "None observed"}</dd></div></dl></section> : null}
    <h3>Why this needs review</h3><p className="body-copy">{device.riskReasons[0] ?? "This known device has no current risk indicators."}</p>
    <h3>What you can do</h3><p className="body-copy">Access changes depend on your router. Sentinel Local will guide you and never store router credentials.</p>
    <div className="inspector-actions"><button onClick={onIdentify}><Search size={17}/>Identify device</button><button onClick={onRestrict}><ShieldCheck size={17}/>Restrict access<small>Simulation · may require router support</small></button><button onClick={onRouter}><ExternalLink size={17}/>Open router controls<small>Opens your router's web interface</small></button></div>
  </aside>;
}
