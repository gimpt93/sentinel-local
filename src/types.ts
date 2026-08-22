export type Severity = "good" | "review" | "risk" | "unknown";
export type ViewId = "overview" | "scans" | "threats" | "privacy" | "network" | "members" | "diagnostics" | "settings";

export interface SecuritySnapshot {
  overall: "protected" | "needs_review" | "at_risk";
  defender: boolean;
  firewall: boolean;
  updatesCurrent: boolean;
  vpnConnected: boolean;
  vpnName: string;
  networkName: string;
  clamDefinitionsAgeDays: number | null;
  observedAt: string;
}

export interface DeviceProfile {
  id: string;
  name: string;
  type: "pc" | "desktop" | "router" | "cellphone" | "laptop" | "tv" | "streaming" | "unknown";
  ip: string;
  mac: string;
  vendor?: string;
  trust: "trusted" | "unknown" | "restricted";
  access: string;
  firstSeen: string;
  lastSeen: string;
  discoverySource: string;
  riskReasons: string[];
}

export interface NetworkTopology {
  gateway: string;
  lanPrefix: string;
  adapter: string;
  devices: DeviceProfile[];
  observedAt: string;
}

export interface ToolStatus {
  id: string;
  name: string;
  installed: boolean;
  version?: string;
  capability: string;
  state: string;
  officialUrl: string;
  openSource: boolean;
}

export interface ScanRequest { scanType: "smart" | "quick" | "full" | "file" | "network"; engine: "defender" | "clamav" | "local"; targets: string[]; exclusions: string[]; consentTimestamp: string; }
export interface ScanProgress { id: string; state: "queued" | "running" | "complete" | "cancelled" | "failed"; percent: number; message: string; startedAt: string; }
export interface ThreatFinding { id: string; engine: string; classification: string; confidence: string; location: string; sha256: string; detectedAt: string; severity: "low" | "medium" | "high"; availableActions: string[]; simulatedState?: string; }
export interface ThreatActionResult { findingId: string; action: "quarantine" | "remove" | "inspect"; status: "completed" | "opened_security" | "unavailable"; message: string; }
export interface DiagnosticResult { id: string; check: string; severity: Severity; evidence: string; recommendation: string; elevationRequired: boolean; }
export interface ActivityEvent { id: string; type: "device" | "scan" | "blocked" | "update" | "vpn"; title: string; detail: string; time: string; }
