import { invoke } from "@tauri-apps/api/core";
import type { ActivityEvent, DeviceProfile, DiagnosticResult, NetworkTopology, ScanProgress, ScanRequest, SecuritySnapshot, ThreatActionResult, ThreatFinding, ToolStatus } from "../types";

const unavailableSnapshot: SecuritySnapshot = { overall: "needs_review", defender: false, firewall: false, updatesCurrent: false, vpnConnected: false, vpnName: "VPN", networkName: "Unavailable outside the desktop app", clamDefinitionsAgeDays: null, observedAt: new Date().toISOString() };

const inTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
async function safeInvoke<T>(command: string, args: Record<string, unknown> | undefined, fallback: T): Promise<T> {
  if (!inTauri()) return fallback;
  try { return await invoke<T>(command, args); } catch { return fallback; }
}

export const bridge = {
  snapshot: () => safeInvoke<SecuritySnapshot>("get_security_snapshot", undefined, unavailableSnapshot),
  topology: () => safeInvoke<NetworkTopology>("discover_network_topology", undefined, { gateway: "", lanPrefix: "", adapter: "No desktop connection", devices: [], observedAt: new Date().toISOString() }),
  devices: () => safeInvoke<DeviceProfile[]>("list_known_devices", undefined, []),
  tools: () => safeInvoke<ToolStatus[]>("detect_supported_tools", undefined, []),
  diagnostics: () => safeInvoke<DiagnosticResult[]>("run_diagnostics", undefined, []),
  findings: () => safeInvoke<ThreatFinding[]>("list_findings", undefined, []),
  events: () => safeInvoke<ActivityEvent[]>("list_activity_events", undefined, []),
  chooseScanTarget: () => safeInvoke<string | null>("choose_scan_target", undefined, null),
  saveDeviceLabel: (id: string, label: string, trust: string, deviceType: DeviceProfile["type"]) => safeInvoke<DeviceProfile>("save_device_label", { id, label, trust, deviceType }, { id, name: label, type: deviceType, ip: "Unavailable", mac: "Unavailable", vendor: "Unknown", trust: trust as DeviceProfile["trust"], access: "Observed", discoverySource: "Local label", firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), riskReasons: [] }),
  startScan: (request: ScanRequest) => safeInvoke<ScanProgress>("start_scan", { request }, { id: crypto.randomUUID(), state: "running", percent: 5, message: "Security checks started", startedAt: new Date().toISOString() }),
  scanProgress: (id: string) => safeInvoke<ScanProgress>("get_scan_progress", { id }, { id, state: "complete", percent: 100, message: "No threats found", startedAt: new Date().toISOString() }),
  cancelScan: (id: string) => safeInvoke<ScanProgress>("cancel_scan", { id }, { id, state: "cancelled", percent: 0, message: "Scan cancelled", startedAt: new Date().toISOString() }),
  threatAction: (findingId: string, action: ThreatActionResult["action"]) => safeInvoke<ThreatActionResult>("manage_threat", { findingId, action }, { findingId, action, status: "unavailable", message: "Threat actions are available in the packaged desktop app." }),
  openVerifiedTool: (toolId: string) => safeInvoke<boolean>("open_verified_tool", { toolId }, false),
  openRouter: (gateway: string) => safeInvoke<boolean>("open_router_admin", { gateway }, false)
};
