import { Globe2, LockKeyhole, Search, ShieldCheck } from "lucide-react";
import type { DeviceProfile, SecuritySnapshot } from "../types";
import { DeviceIcon } from "./DeviceIcon";

const positions: Record<string, string> = { phone: "device-pos-1", laptop: "device-pos-2", tv: "device-pos-3", unknown: "device-pos-4" };

function Node({ device, selected, onSelect }: { device: DeviceProfile; selected: boolean; onSelect: () => void }) {
  return <button className={`device-node ${positions[device.id] ?? ""} ${device.trust === "unknown" ? "unknown" : ""} ${selected ? "selected" : ""}`} onClick={onSelect} aria-label={`${device.name}, ${device.trust}`}>
    <span className="device-orb"><DeviceIcon type={device.type}/><span className={`node-state ${device.trust === "unknown" ? "review" : "good"}`}>{device.trust === "unknown" ? "!" : "✓"}</span></span>
    <strong>{device.name}</strong><small>{device.ip}</small><span className="trust-line">Trust: <b>{device.trust === "unknown" ? "Unknown" : "Trusted"}</b></span><span>Access: {device.access}</span>
  </button>;
}

export function TopologyMap({ devices, snapshot, selectedId, onSelect, onOpenView }: { devices: DeviceProfile[]; snapshot: SecuritySnapshot; selectedId: string; onSelect: (id: string) => void; onOpenView: (view: "scans" | "privacy") => void }) {
  const pc = devices.find(d => d.type === "pc") ?? devices[0];
  const router = devices.find(d => d.type === "router") ?? devices[1];
  const endpoints = devices.filter(d => !["pc", "router"].includes(d.type)).slice(0, 4);
  return <section className="map-canvas" aria-label="Home network topology">
    <p className="map-hint"><Search size={15}/> Select any device for details</p>
    <svg className="connections" viewBox="0 0 1000 560" preserveAspectRatio="none" aria-hidden="true">
      <path d="M505 70 L505 160 L505 255"/><path d="M250 300 L475 300"/><path d="M535 300 L760 430"/><path d="M520 325 L565 430"/><path d="M500 325 L375 430"/><path d="M480 315 L185 430"/>
    </svg>
    <div className="internet-node"><span><Globe2 size={30}/></span><strong>Internet</strong><small>Public network</small></div>
    <div className="vpn-boundary"><LockKeyhole size={15}/><strong>{snapshot.vpnName} — {snapshot.vpnConnected ? "Connected" : "Review"}</strong><small>Privacy boundary {snapshot.vpnConnected ? "active" : "inactive"}</small></div>
    <div className="pc-summary"><strong>{pc.name}</strong><small>{pc.ip}</small><ul><li>Windows Security: {snapshot.defender ? "Active" : "Review"}</li><li>Firewall: {snapshot.firewall ? "Active" : "Review"}</li><li>ClamAV: On-demand</li><li>Last scan: Today</li></ul></div>
    <button className="core-node pc-node" onClick={() => onSelect(pc.id)}><span><DeviceIcon type="pc" size={34}/></span><i>✓</i></button>
    <button className="outline-action scan-pc" onClick={() => onOpenView("scans")}><Search size={15}/> Scan this PC</button>
    <button className="core-node router-node" onClick={() => onSelect(router.id)}><span><DeviceIcon type="router" size={34}/></span><i>✓</i></button>
    <div className="router-label"><strong>{router.name}</strong><small>{router.ip}<br/>Router firewall: Observed</small></div>
    <button className="outline-action check-vpn" onClick={() => onOpenView("privacy")}><ShieldCheck size={15}/> Check VPN</button>
    {endpoints.map(device => <Node key={device.id} device={device} selected={selectedId === device.id} onSelect={() => onSelect(device.id)} />)}
    <div className="mobile-topology" aria-label="Network relationships">
      <div><Globe2/><span><strong>Internet</strong><small>through {snapshot.vpnName} · {snapshot.vpnConnected ? "VPN connected" : "VPN needs review"}</small></span></div>
      <div><DeviceIcon type="router"/><span><strong>{router.name}</strong><small>{router.ip} · private gateway</small></span></div>
      <div><DeviceIcon type="pc"/><span><strong>{pc.name}</strong><small>Windows Security and firewall {snapshot.defender && snapshot.firewall ? "active" : "need review"}</small></span></div>
      {endpoints.map(device => <button key={`mobile-${device.id}`} onClick={() => onSelect(device.id)}><DeviceIcon type={device.type}/><span><strong>{device.name}</strong><small>{device.trust} · {device.access}</small></span><b>{device.trust === "unknown" ? "Review" : "Known"}</b></button>)}
    </div>
  </section>;
}
