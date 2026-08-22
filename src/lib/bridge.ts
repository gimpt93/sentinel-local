import { invoke } from "@tauri-apps/api/core";
import type { DeviceProfile, DiagnosticResult, NetworkTopology, ScanProgress, ScanRequest, SecuritySnapshot, ThreatFinding, ToolStatus } from "../types";
import { fallbackDevices, fallbackDiagnostics, fallbackFindings, fallbackSnapshot, fallbackTools } from "../data/fallback";

const inTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
async function safeInvoke<T>(command: string, args: Record<string, unknown> | undefined, fallback: T): Promise<T> {
  if (!inTauri()) return fallback;
  try { return await invoke<T>(command, args); } catch { return fallback; }
}

export const bridge = {
  snapshot: () => safeInvoke<SecuritySnapshot>("get_security_snapshot", undefined, fallbackSnapshot),
  topology: () => safeInvoke<NetworkTopology>("discover_network_topology", undefined, { gateway: "192.168.1.1", lanPrefix: "192.168.1.0/24", adapter: "Wi-Fi", devices: fallbackDevices, observedAt: new Date().toISOString() }),
  devices: () => safeInvoke<DeviceProfile[]>("list_known_devices", undefined, fallbackDevices),
  tools: () => safeInvoke<ToolStatus[]>("detect_supported_tools", undefined, fallbackTools),
  diagnostics: () => safeInvoke<DiagnosticResult[]>("run_diagnostics", undefined, fallbackDiagnostics),
  findings: () => safeInvoke<ThreatFinding[]>("list_findings", undefined, fallbackFindings),
  chooseScanTarget: () => safeInvoke<string | null>("choose_scan_target", undefined, null),
  saveDeviceLabel: (id: string, label: string, trust: string) => safeInvoke<DeviceProfile>("save_device_label", { id, label, trust }, fallbackDevices.find(d => d.id === id) ?? fallbackDevices[0]),
  startScan: (request: ScanRequest) => safeInvoke<ScanProgress>("start_scan", { request }, { id: crypto.randomUUID(), state: "running", percent: 5, message: "Security checks started", startedAt: new Date().toISOString() }),
  scanProgress: (id: string) => safeInvoke<ScanProgress>("get_scan_progress", { id }, { id, state: "complete", percent: 100, message: "No threats found", startedAt: new Date().toISOString() }),
  cancelScan: (id: string) => safeInvoke<ScanProgress>("cancel_scan", { id }, { id, state: "cancelled", percent: 0, message: "Scan cancelled", startedAt: new Date().toISOString() }),
  openVerifiedTool: (toolId: string) => safeInvoke<boolean>("open_verified_tool", { toolId }, false),
  openRouter: (gateway: string) => safeInvoke<boolean>("open_router_admin", { gateway }, false)
};
