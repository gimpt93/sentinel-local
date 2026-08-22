import { useEffect, useMemo, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Header } from "./components/Header";
import { StatusStrip } from "./components/StatusStrip";
import { TopologyMap } from "./components/TopologyMap";
import { DeviceInspector } from "./components/DeviceInspector";
import { EventTimeline } from "./components/EventTimeline";
import { ProtectionDrawer } from "./components/ProtectionDrawer";
import { DiagnosticsView, MembersView, NetworkView, PrivacyView, ScansView, SettingsView, ThreatsView } from "./components/Views";
import { bridge } from "./lib/bridge";
import type { ActivityEvent, DeviceProfile, DiagnosticResult, ScanProgress, ScanRequest, SecuritySnapshot, ThreatFinding, ToolStatus, ViewId } from "./types";

const emptySnapshot: SecuritySnapshot = { overall:"needs_review", defender:false, firewall:false, updatesCurrent:false, vpnConnected:false, vpnName:"VPN", networkName:"Detecting network…", clamDefinitionsAgeDays:null, observedAt:new Date().toISOString() };

const viewCopy: Record<ViewId, [string, string]> = {
  overview: ["Home security map", "Understand your network and stay protected."], scans: ["Scanning tools", "Run explicit, non-destructive local security checks."], threats: ["Threat management", "Review evidence before taking action."], privacy: ["Privacy controls", "Understand and manage each privacy layer."], network: ["Network settings", "Review your active connection and router path."], members: ["Network members", "Identify and organize locally observed devices."], diagnostics: ["Diagnostics & repair", "Troubleshoot with evidence and safe next steps."], settings: ["Settings", "Manage local privacy and accessibility preferences."]
};

export default function App() {
  const [view, setView] = useState<ViewId>("overview");
  const [snapshot, setSnapshot] = useState<SecuritySnapshot>(emptySnapshot);
  const [devices, setDevices] = useState<DeviceProfile[]>([]);
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [diagnostics, setDiagnostics] = useState<DiagnosticResult[]>([]);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [findings, setFindings] = useState<ThreatFinding[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [scan, setScan] = useState<ScanProgress>();
  const [toast, setToast] = useState<string>();
  const [gateway, setGateway] = useState("192.168.1.1");
  const [adapter, setAdapter] = useState("Wi-Fi · HomeWiFi_5G");

  const load = async () => {
    const [nextSnapshot, topology, nextTools, nextEvents, nextFindings] = await Promise.all([bridge.snapshot(), bridge.topology(), bridge.tools(), bridge.events(), bridge.findings()]);
    setSnapshot(nextSnapshot); setDevices(topology.devices); setTools(nextTools); setEvents(nextEvents); setFindings(nextFindings); setGateway(topology.gateway); setAdapter(topology.adapter); setSelectedId(current => current || topology.devices.find(d => d.trust === "unknown")?.id || topology.devices[0]?.id || ""); setLoaded(true);
  };
  useEffect(() => { void load(); }, []);
  useEffect(() => { if (!toast) return; const id = window.setTimeout(() => setToast(undefined), 4200); return () => window.clearTimeout(id); }, [toast]);
  useEffect(() => { if (!scan || scan.state !== "running") return; const id = window.setTimeout(async () => setScan(await bridge.scanProgress(scan.id)), 1500); return () => clearTimeout(id); }, [scan]);

  const selected = useMemo(() => devices.find(d => d.id === selectedId), [devices, selectedId]);
  const reviewCount = useMemo(() => devices.filter(d => d.trust === "unknown").length, [devices]);
  const startScan = async (scanType: ScanRequest["scanType"], engine: ScanRequest["engine"] = "local") => {
    const result = await bridge.startScan({ scanType, engine, targets: [], exclusions: [], consentTimestamp: new Date().toISOString() }); setScan(result); setToast(`${scanType === "smart" ? "Smart" : scanType} scan started locally.`);
  };
  const startClamScan = async () => { const target = await bridge.chooseScanTarget(); if (!target) { setToast("No file selected."); return; } const result = await bridge.startScan({ scanType:"file", engine:"clamav", targets:[target], exclusions:[], consentTimestamp:new Date().toISOString() }); setScan(result); setToast("ClamAV on-demand scan started for the selected file."); };
  const saveLabel = async (id: string, label: string, trust: string) => { await bridge.saveDeviceLabel(id, label, trust); setDevices(current => current.map(d => d.id === id ? { ...d, name: label, trust: trust as DeviceProfile["trust"] } : d)); setToast("Local device label saved."); };
  const openTool = async (id: string) => { const ok = await bridge.openVerifiedTool(id); setToast(ok ? "Opened verified destination." : "Verified tool link is available in the packaged app."); };
  const openRouter = async () => { const ok = await bridge.openRouter(gateway); setToast(ok ? "Opened your private gateway." : `Router controls: http://${gateway}`); };
  const runDiagnostics = async () => { setDiagnostics(await bridge.diagnostics()); setToast("Diagnostics refreshed using live local checks."); };
  const refreshFindings = async () => { setFindings(await bridge.findings()); setToast("Live findings refreshed."); };

  return <div className="app-shell">
    <Sidebar view={view} overall={snapshot.overall} reviewCount={reviewCount} onChange={setView}/>
    <main className="app-main">
      <Header title={viewCopy[view][0]} subtitle={viewCopy[view][1]} networkName={snapshot.networkName} scanning={scan?.state === "running"} onScan={() => { setView("scans"); void startScan("smart"); }}/>
      {!loaded ? <div className="loading-state" role="status"><span className="spinner"/><h2>Reading local security state</h2><p>No sample data is shown while Windows and network checks complete.</p></div> : view === "overview" ? <>
        <StatusStrip snapshot={snapshot} reviewCount={reviewCount}/>
        <div className="overview-layout"><TopologyMap devices={devices} snapshot={snapshot} selectedId={selectedId} onSelect={setSelectedId} onOpenView={setView}/><DeviceInspector device={selected} onClose={() => setSelectedId("")} onIdentify={() => setView("members")} onRestrict={() => setToast("Restriction simulated. Review router support before changing access.")} onRouter={openRouter}/></div>
        <EventTimeline events={events}/><ProtectionDrawer tools={tools} onOpen={openTool}/>
      </> : view === "scans" ? <ScansView tools={tools} progress={scan} onStart={startScan} onClamScan={startClamScan} onCancel={async () => scan && setScan(await bridge.cancelScan(scan.id))}/>
      : view === "threats" ? <ThreatsView findings={findings} onRefresh={refreshFindings}/> : view === "privacy" ? <PrivacyView tools={tools} onOpen={openTool}/>
      : view === "network" ? <NetworkView gateway={gateway} adapter={adapter} onRouter={openRouter}/>
      : view === "members" ? <MembersView devices={devices} onSave={saveLabel}/>
      : view === "diagnostics" ? <DiagnosticsView results={diagnostics} onRun={runDiagnostics}/>
      : <SettingsView/>}
    </main>
    {toast && <div className="toast" role="status">{toast}</div>}
  </div>;
}
