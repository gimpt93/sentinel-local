import { AlertTriangle, ExternalLink, Search, ShieldCheck, X } from "lucide-react";
import type { DeviceProfile } from "../types";

export function DeviceInspector({ device, onClose, onIdentify, onRestrict, onRouter }: { device?: DeviceProfile; onClose: () => void; onIdentify: () => void; onRestrict: () => void; onRouter: () => void }) {
  if (!device) return <aside className="inspector empty-inspector"><ShieldCheck size={36}/><h2>Select a device</h2><p>Choose a node on the security map to review its local observations.</p></aside>;
  return <aside className="inspector" aria-label={`${device.name} details`}>
    <button className="inspector-close" onClick={onClose} aria-label="Close inspector"><X size={20}/></button>
    <div className="inspector-title"><AlertTriangle className={device.trust === "unknown" ? "review" : "good"}/><div><h2>{device.name}</h2><p>{device.ip}</p></div></div>
    <span className={`badge ${device.trust === "unknown" ? "review-badge" : "good-badge"}`}>{device.trust === "unknown" ? "Needs review" : "Trusted device"}</span>
    <dl className="detail-list"><div><dt>First seen</dt><dd>{device.firstSeen}</dd></div><div><dt>Last seen</dt><dd>{device.lastSeen}</dd></div><div><dt>IP address</dt><dd>{device.ip}</dd></div><div><dt>MAC address</dt><dd>{device.mac}</dd></div><div><dt>Vendor (observed)</dt><dd>{device.vendor ?? "Not identified"}</dd></div><div><dt>Discovery</dt><dd>{device.discoverySource}</dd></div></dl>
    <h3>Why this needs review</h3><p className="body-copy">{device.riskReasons[0] ?? "This known device has no current risk indicators."}</p>
    <h3>What you can do</h3><p className="body-copy">Access changes depend on your router. Sentinel Local will guide you and never store router credentials.</p>
    <div className="inspector-actions"><button onClick={onIdentify}><Search size={17}/>Identify device</button><button onClick={onRestrict}><ShieldCheck size={17}/>Restrict access<small>Simulation · may require router support</small></button><button onClick={onRouter}><ExternalLink size={17}/>Open router controls<small>Opens your router's web interface</small></button></div>
  </aside>;
}
