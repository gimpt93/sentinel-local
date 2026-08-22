import type { ActivityEvent, DeviceProfile, DiagnosticResult, SecuritySnapshot, ThreatFinding, ToolStatus } from "../types";

export const fallbackSnapshot: SecuritySnapshot = {
  overall: "needs_review", defender: true, firewall: true, updatesCurrent: true,
  vpnConnected: true, vpnName: "Proton VPN", networkName: "HomeWiFi_5G",
  clamDefinitionsAgeDays: 0, observedAt: new Date().toISOString()
};

export const fallbackDevices: DeviceProfile[] = [
  { id: "this-pc", name: "This PC (You)", type: "pc", ip: "192.168.1.100", mac: "Local device", trust: "trusted", access: "Full", firstSeen: "Known device", lastSeen: "Now", discoverySource: "Windows", riskReasons: [] },
  { id: "router", name: "Home router", type: "router", ip: "192.168.1.1", mac: "Gateway", trust: "trusted", access: "Network control", firstSeen: "Known device", lastSeen: "Now", discoverySource: "Default route", riskReasons: [] },
  { id: "phone", name: "Alex's Phone", type: "phone", ip: "192.168.1.101", mac: "Randomized", trust: "trusted", access: "Full", firstSeen: "Jun 18", lastSeen: "1 min ago", discoverySource: "Neighbor table", riskReasons: [] },
  { id: "laptop", name: "Work Laptop", type: "laptop", ip: "192.168.1.102", mac: "Private", trust: "trusted", access: "Full", firstSeen: "May 4", lastSeen: "2 min ago", discoverySource: "Neighbor table", riskReasons: [] },
  { id: "tv", name: "Living Room TV", type: "tv", ip: "192.168.1.103", mac: "Private", vendor: "Samsung (observed)", trust: "trusted", access: "Internet only", firstSeen: "Apr 22", lastSeen: "5 min ago", discoverySource: "SSDP", riskReasons: [] },
  { id: "unknown", name: "Unknown device", type: "unknown", ip: "192.168.1.104", mac: "3C:52:82:9A:1B:7C", vendor: "Amazon Technologies (observed)", trust: "unknown", access: "Internet only", firstSeen: "Today, 9:42 AM", lastSeen: "8 min ago", discoverySource: "Neighbor table", riskReasons: ["Not in your known devices list", "Recently joined this network"] }
];

export const fallbackTools: ToolStatus[] = [
  { id: "defender", name: "Windows Security", installed: true, capability: "Real-time protection", state: "Active", officialUrl: "ms-settings:windowsdefender", openSource: false },
  { id: "clamav", name: "ClamAV (on-demand)", installed: false, capability: "Manual malware scanning", state: "Not detected", officialUrl: "https://www.clamav.net/downloads", openSource: true },
  { id: "simplewall", name: "simplewall (WFP)", installed: false, capability: "Windows Filtering Platform control", state: "Not detected", officialUrl: "https://github.com/henrypp/simplewall/releases", openSource: true },
  { id: "proton", name: "Proton VPN Free", installed: true, capability: "VPN connection", state: "Connected", officialUrl: "https://protonvpn.com/download-windows", openSource: true },
  { id: "ublock", name: "uBlock Origin", installed: false, capability: "Browser content filtering", state: "Browser setup", officialUrl: "https://github.com/gorhill/uBlock", openSource: true }
];

export const fallbackEvents: ActivityEvent[] = [
  { id: "e1", type: "device", title: "Unknown device joined", detail: "192.168.1.104", time: "11:05 AM" },
  { id: "e2", type: "vpn", title: "Proton VPN connected", detail: "VPN boundary active", time: "10:58 AM" },
  { id: "e3", type: "blocked", title: "Blocked connection", detail: "Outbound rule matched", time: "10:47 AM" },
  { id: "e4", type: "update", title: "Definitions updated", detail: "Protection data current", time: "10:30 AM" },
  { id: "e5", type: "scan", title: "Smart scan completed", detail: "No threats found", time: "10:15 AM" }
];

export const fallbackDiagnostics: DiagnosticResult[] = [
  { id: "d1", check: "Windows Security", severity: "good", evidence: "Microsoft Defender reports active protection.", recommendation: "No action needed.", elevationRequired: false },
  { id: "d2", check: "Firewall profiles", severity: "good", evidence: "Windows firewall is enabled.", recommendation: "Keep all active profiles enabled.", elevationRequired: false },
  { id: "d3", check: "Unknown network member", severity: "review", evidence: "A device not yet labeled was observed on this LAN.", recommendation: "Identify it before changing router access.", elevationRequired: false },
  { id: "d4", check: "Router reachability", severity: "good", evidence: "The private default gateway is reachable.", recommendation: "No action needed.", elevationRequired: false }
];

export const fallbackFindings: ThreatFinding[] = [];
