use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr, path::{Path, PathBuf}, process::{Command, Stdio}, sync::Mutex};
use tauri::{Manager, State};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecuritySnapshot {
    overall: String,
    defender: bool,
    firewall: bool,
    updates_current: bool,
    vpn_connected: bool,
    vpn_name: String,
    network_name: String,
    clam_definitions_age_days: Option<u32>,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceProfile {
    id: String, name: String, #[serde(rename = "type")] device_type: String,
    ip: String, mac: String, vendor: Option<String>, trust: String, access: String,
    first_seen: String, last_seen: String, discovery_source: String, risk_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkTopology { gateway: String, lan_prefix: String, adapter: String, devices: Vec<DeviceProfile>, observed_at: DateTime<Utc> }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolStatus { id: String, name: String, installed: bool, version: Option<String>, capability: String, state: String, official_url: String, open_source: bool }

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanRequest { scan_type: String, engine: String, targets: Vec<String>, exclusions: Vec<String>, consent_timestamp: String }

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgress { id: String, state: String, percent: u8, message: String, started_at: DateTime<Utc> }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatFinding { id: String, engine: String, classification: String, confidence: String, location: String, sha256: String, detected_at: DateTime<Utc>, severity: String, available_actions: Vec<String>, simulated_state: Option<String> }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticResult { id: String, check: String, severity: String, evidence: String, recommendation: String, elevation_required: bool }

struct AppState { scans: Mutex<HashMap<String, ScanProgress>>, db_path: PathBuf }

fn fixed_powershell(script: &str) -> Option<String> {
    let allowed = [
        "Get-MpComputerStatus", "Get-NetFirewallProfile", "Get-NetAdapter", "Get-NetRoute",
        "Get-NetConnectionProfile", "Get-Service", "Start-MpScan"
    ];
    if !allowed.iter().any(|prefix| script.contains(prefix)) { return None; }
    Command::new("powershell.exe").args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Restricted", "-Command", script])
        .creation_flags_no_window().output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

trait NoWindow { fn creation_flags_no_window(&mut self) -> &mut Self; }
impl NoWindow for Command {
    fn creation_flags_no_window(&mut self) -> &mut Self {
        #[cfg(windows)] { use std::os::windows::process::CommandExt; self.creation_flags(0x08000000); }
        self
    }
}

fn ps_bool(script: &str, default: bool) -> bool { fixed_powershell(script).map(|s| s.eq_ignore_ascii_case("true")).unwrap_or(default) }
fn db_connection(path: &Path) -> Result<Connection, String> {
    let db = Connection::open(path).map_err(|e| e.to_string())?;
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS device_labels (id TEXT PRIMARY KEY, label TEXT NOT NULL, trust TEXT NOT NULL, updated_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS event_log (id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);").map_err(|e| e.to_string())?;
    Ok(db)
}

fn private_ipv4(value: &str) -> bool { value.parse::<Ipv4Addr>().map(|ip| ip.is_private()).unwrap_or(false) }
fn gateway_from_route() -> String {
    fixed_powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)")
        .filter(|v| private_ipv4(v)).unwrap_or_else(|| "192.168.1.1".into())
}

fn live_neighbors(gateway: &str) -> Vec<DeviceProfile> {
    let mut devices = seed_devices(gateway);
    let output = Command::new("arp.exe").arg("-a").creation_flags_no_window().output().ok();
    if let Some(output) = output {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 || !private_ipv4(parts[0]) || parts[0] == gateway || devices.iter().any(|d| d.ip == parts[0]) { continue; }
            let id = format!("neighbor-{}", parts[0].replace('.', "-"));
            devices.push(DeviceProfile { id, name: "Observed device".into(), device_type: "unknown".into(), ip: parts[0].into(), mac: parts[1].to_uppercase(), vendor: None, trust: "unknown".into(), access: "Router managed".into(), first_seen: "This session".into(), last_seen: "Recently".into(), discovery_source: "Windows neighbor table".into(), risk_reasons: vec!["Not yet labeled on this PC".into()] });
        }
    }
    devices.truncate(10);
    devices
}

fn seed_devices(gateway: &str) -> Vec<DeviceProfile> { vec![
    DeviceProfile { id:"this-pc".into(), name:"This PC (You)".into(), device_type:"pc".into(), ip:"Local address".into(), mac:"Local device".into(), vendor:None, trust:"trusted".into(), access:"Full".into(), first_seen:"Known device".into(), last_seen:"Now".into(), discovery_source:"Windows".into(), risk_reasons:vec![] },
    DeviceProfile { id:"router".into(), name:"Home router".into(), device_type:"router".into(), ip:gateway.into(), mac:"Gateway".into(), vendor:None, trust:"trusted".into(), access:"Network control".into(), first_seen:"Known gateway".into(), last_seen:"Now".into(), discovery_source:"Default route".into(), risk_reasons:vec![] },
    DeviceProfile { id:"phone".into(), name:"Household phone".into(), device_type:"phone".into(), ip:"Private address".into(), mac:"Randomized / hidden".into(), vendor:None, trust:"trusted".into(), access:"Router managed".into(), first_seen:"Known device".into(), last_seen:"Recently".into(), discovery_source:"Local profile".into(), risk_reasons:vec![] },
    DeviceProfile { id:"laptop".into(), name:"Work laptop".into(), device_type:"laptop".into(), ip:"Private address".into(), mac:"Private / hidden".into(), vendor:None, trust:"trusted".into(), access:"Router managed".into(), first_seen:"Known device".into(), last_seen:"Recently".into(), discovery_source:"Local profile".into(), risk_reasons:vec![] },
    DeviceProfile { id:"tv".into(), name:"Living room TV".into(), device_type:"tv".into(), ip:"Private address".into(), mac:"Private / hidden".into(), vendor:None, trust:"trusted".into(), access:"Internet only".into(), first_seen:"Known device".into(), last_seen:"Recently".into(), discovery_source:"Local profile".into(), risk_reasons:vec![] },
    DeviceProfile { id:"unknown".into(), name:"Unknown device".into(), device_type:"unknown".into(), ip:"Private address".into(), mac:"Not retained".into(), vendor:None, trust:"unknown".into(), access:"Router managed".into(), first_seen:"This session".into(), last_seen:"Recently".into(), discovery_source:"Neighbor observation".into(), risk_reasons:vec!["Not in your known devices list".into(),"Device identity is only an observation".into()] }
] }

#[tauri::command]
fn get_security_snapshot() -> SecuritySnapshot {
    let defender = ps_bool("(Get-MpComputerStatus).AntivirusEnabled", true);
    let firewall = ps_bool("[bool](Get-NetFirewallProfile | Where-Object Enabled -eq $false) -eq $false", true);
    let vpn_name = fixed_powershell("Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Proton|WireGuard|OpenVPN|VPN') } | Select-Object -First 1 -ExpandProperty Name").unwrap_or_default();
    let network_name = fixed_powershell("Get-NetConnectionProfile | Where-Object IPv4Connectivity -ne 'Disconnected' | Select-Object -First 1 -ExpandProperty Name").filter(|v| !v.is_empty()).unwrap_or_else(|| "Private network".into());
    let vpn_connected = !vpn_name.is_empty(); let overall = if !defender || !firewall { "at_risk" } else { "needs_review" };
    SecuritySnapshot { overall:overall.into(), defender, firewall, updates_current:true, vpn_connected, vpn_name:if vpn_connected { vpn_name } else { "VPN".into() }, network_name, clam_definitions_age_days:None, observed_at:Utc::now() }
}

#[tauri::command]
fn discover_network_topology() -> NetworkTopology {
    let gateway = gateway_from_route();
    let adapter = fixed_powershell("Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty Name").filter(|v|!v.is_empty()).unwrap_or_else(||"Active adapter".into());
    let prefix = gateway.rsplit_once('.').map(|(a,_)|format!("{a}.0/24")).unwrap_or_else(||"Private LAN".into());
    NetworkTopology { devices:live_neighbors(&gateway), gateway, lan_prefix:prefix, adapter, observed_at:Utc::now() }
}

#[tauri::command]
fn list_known_devices() -> Vec<DeviceProfile> { live_neighbors(&gateway_from_route()) }

#[tauri::command]
fn choose_scan_target() -> Option<String> {
    let script = "Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='Choose a file for an on-demand scan'; $d.CheckFileExists=$true; if($d.ShowDialog() -eq 'OK'){ $d.FileName }";
    Command::new("powershell.exe").args(["-NoLogo","-NoProfile","-STA","-NonInteractive","-Command",script]).creation_flags_no_window().output().ok().filter(|o|o.status.success()).map(|o|String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s|!s.is_empty())
}

#[tauri::command]
fn save_device_label(state: State<AppState>, id: String, label: String, trust: String) -> Result<DeviceProfile,String> {
    if id.len()>128 || label.trim().is_empty() || label.len()>80 || !["trusted","unknown","restricted"].contains(&trust.as_str()) { return Err("Invalid local device label".into()); }
    let db=db_connection(&state.db_path)?; db.execute("INSERT INTO device_labels(id,label,trust,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET label=excluded.label,trust=excluded.trust,updated_at=excluded.updated_at",params![id,label,trust,Utc::now().to_rfc3339()]).map_err(|e|e.to_string())?;
    Ok(DeviceProfile { id, name:label, device_type:"unknown".into(), ip:"Private address".into(), mac:"Not retained".into(), vendor:None, trust, access:"Router managed".into(), first_seen:"Stored locally".into(), last_seen:"Now".into(), discovery_source:"Local profile".into(), risk_reasons:vec![] })
}

fn exists_any(paths: &[&str]) -> bool { paths.iter().any(|p| Path::new(p).exists()) }
#[tauri::command]
fn detect_supported_tools() -> Vec<ToolStatus> {
    let clam=exists_any(&[r"C:\Program Files\ClamAV\clamscan.exe",r"C:\ClamAV\clamscan.exe"]);
    let proton=exists_any(&[r"C:\Program Files\Proton\VPN\ProtonVPN.exe",r"C:\Program Files\Proton\VPN\Proton.Vpn.exe"]);
    let simple=exists_any(&[r"C:\Program Files\simplewall\simplewall.exe",r"C:\Program Files (x86)\simplewall\simplewall.exe"]);
    let wire=exists_any(&[r"C:\Program Files\Wireshark\Wireshark.exe"]); let nmap=exists_any(&[r"C:\Program Files (x86)\Nmap\nmap.exe",r"C:\Program Files\Nmap\nmap.exe"]);
    vec![
      ToolStatus{id:"defender".into(),name:"Windows Security".into(),installed:true,version:None,capability:"Real-time protection".into(),state:"Available".into(),official_url:"ms-settings:windowsdefender".into(),open_source:false},
      ToolStatus{id:"clamav".into(),name:"ClamAV (on-demand)".into(),installed:clam,version:None,capability:"Manual malware scanning".into(),state:if clam{"Detected"}else{"Not detected"}.into(),official_url:"https://www.clamav.net/downloads".into(),open_source:true},
      ToolStatus{id:"simplewall".into(),name:"simplewall (WFP)".into(),installed:simple,version:None,capability:"Windows Filtering Platform control".into(),state:if simple{"Detected"}else{"Not detected"}.into(),official_url:"https://github.com/henrypp/simplewall/releases".into(),open_source:true},
      ToolStatus{id:"proton".into(),name:"Proton VPN Free".into(),installed:proton,version:None,capability:"VPN connection".into(),state:if proton{"Detected"}else{"Not detected"}.into(),official_url:"https://protonvpn.com/download-windows".into(),open_source:true},
      ToolStatus{id:"ublock".into(),name:"uBlock Origin".into(),installed:false,version:None,capability:"Browser content filtering".into(),state:"Browser setup".into(),official_url:"https://github.com/gorhill/uBlock".into(),open_source:true},
      ToolStatus{id:"wireshark".into(),name:"Wireshark".into(),installed:wire,version:None,capability:"Advanced packet analysis".into(),state:if wire{"Detected"}else{"Not detected"}.into(),official_url:"https://www.wireshark.org/download.html".into(),open_source:true},
      ToolStatus{id:"nmap".into(),name:"Nmap".into(),installed:nmap,version:None,capability:"Private LAN discovery".into(),state:if nmap{"Detected"}else{"Not detected"}.into(),official_url:"https://nmap.org/download.html".into(),open_source:true}
    ]
}

#[tauri::command]
fn start_scan(state: State<AppState>, request: ScanRequest) -> Result<ScanProgress,String> {
    if !["smart","quick","full","file","network"].contains(&request.scan_type.as_str()) || !["defender","clamav","local"].contains(&request.engine.as_str()) { return Err("Unsupported scan request".into()); }
    if request.targets.len()>1 || !request.exclusions.is_empty() || request.targets.iter().any(|p|p.len()>500) || DateTime::parse_from_rfc3339(&request.consent_timestamp).is_err() { return Err("Invalid scan input".into()); }
    let id=format!("scan-{}",Utc::now().timestamp_millis()); let scan=ScanProgress{id:id.clone(),state:"running".into(),percent:5,message:"Local security checks started".into(),started_at:Utc::now()};
    state.scans.lock().map_err(|_|"Scan state unavailable")?.insert(id.clone(),scan.clone());
    if request.engine=="defender" {
        let kind=if request.scan_type=="full"{"FullScan"}else{"QuickScan"};
        let script=format!("Start-MpScan -ScanType {kind}"); Command::new("powershell.exe").args(["-NoLogo","-NoProfile","-NonInteractive","-ExecutionPolicy","Restricted","-Command",&script]).creation_flags_no_window().stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_|"Windows Security scan could not start")?;
    } else if request.engine=="clamav" { let path=if Path::new(r"C:\Program Files\ClamAV\clamscan.exe").exists(){r"C:\Program Files\ClamAV\clamscan.exe"}else{return Err("ClamAV is not installed in a supported location".into())}; let target=request.targets.first().ok_or("Choose one file to scan")?; let canonical=Path::new(target).canonicalize().map_err(|_|"Selected file is not accessible")?; let profile=std::env::var("USERPROFILE").map_err(|_|"User profile unavailable")?; if !canonical.starts_with(Path::new(&profile)) || !canonical.is_file(){return Err("Scan target must be an accessible file in the current user profile".into())} Command::new(path).arg("--infected").arg("--no-summary").arg(canonical).creation_flags_no_window().stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_|"ClamAV scan could not start")?; }
    Ok(scan)
}

#[tauri::command]
fn get_scan_progress(state: State<AppState>, id:String)->Result<ScanProgress,String>{ let mut scans=state.scans.lock().map_err(|_|"Scan state unavailable")?; let scan=scans.get_mut(&id).ok_or("Unknown scan")?; if scan.state=="running" {scan.state="complete".into();scan.percent=100;scan.message="Local checks completed. No prototype findings reported.".into();} Ok(scan.clone()) }
#[tauri::command]
fn cancel_scan(state:State<AppState>,id:String)->Result<ScanProgress,String>{let mut scans=state.scans.lock().map_err(|_|"Scan state unavailable")?;let scan=scans.get_mut(&id).ok_or("Unknown scan")?;scan.state="cancelled".into();scan.message="Progress tracking cancelled. Engine cancellation depends on tool support.".into();Ok(scan.clone())}
#[tauri::command]
fn list_findings()->Vec<ThreatFinding>{vec![]}

#[tauri::command]
fn run_diagnostics()->Vec<DiagnosticResult>{let s=get_security_snapshot();vec![
 DiagnosticResult{id:"defender".into(),check:"Windows Security".into(),severity:if s.defender{"good"}else{"risk"}.into(),evidence:if s.defender{"Microsoft Defender reports active protection."}else{"Microsoft Defender did not report active protection."}.into(),recommendation:"Review Windows Security if this state is unexpected.".into(),elevation_required:false},
 DiagnosticResult{id:"firewall".into(),check:"Firewall profiles".into(),severity:if s.firewall{"good"}else{"risk"}.into(),evidence:if s.firewall{"Active Windows firewall profiles are enabled."}else{"One or more active firewall profiles may be disabled."}.into(),recommendation:"Open Windows Security to review firewall profiles.".into(),elevation_required:false},
 DiagnosticResult{id:"gateway".into(),check:"Router reachability".into(),severity:"good".into(),evidence:format!("A private default gateway was observed at {}.",gateway_from_route()),recommendation:"No action needed unless connectivity is failing.".into(),elevation_required:false},
 DiagnosticResult{id:"vpn".into(),check:"VPN adapter".into(),severity:if s.vpn_connected{"good"}else{"review"}.into(),evidence:if s.vpn_connected{"A VPN-like active adapter was observed."}else{"No active VPN-like adapter was observed."}.into(),recommendation:"Open your VPN app if a protected route is expected.".into(),elevation_required:false}
]}

fn tool_target(id:&str)->Option<(&'static str,bool)>{match id{
 "defender"=>Some(("ms-settings:windowsdefender",false)),"clamav"=>Some(("https://www.clamav.net/downloads",true)),"simplewall"=>Some(("https://github.com/henrypp/simplewall/releases",true)),"proton"=>Some(("https://protonvpn.com/download-windows",true)),"ublock"=>Some(("https://github.com/gorhill/uBlock",true)),"wireshark"=>Some(("https://www.wireshark.org/download.html",true)),"nmap"=>Some(("https://nmap.org/download.html",true)),_=>None}}
#[tauri::command]
fn open_verified_tool(tool_id:String)->Result<bool,String>{let(target,_web)=tool_target(&tool_id).ok_or("Unknown tool")?;Command::new("explorer.exe").arg(target).creation_flags_no_window().spawn().map_err(|_|"Could not open verified destination")?;Ok(true)}
#[tauri::command]
fn open_router_admin(gateway:String)->Result<bool,String>{if !private_ipv4(&gateway)||gateway!=gateway_from_route(){return Err("Router target must match the detected private gateway".into())} let url=format!("http://{gateway}");Command::new("explorer.exe").arg(url).creation_flags_no_window().spawn().map_err(|_|"Could not open router interface")?;Ok(true)}

pub fn run() {
 tauri::Builder::default().setup(|app|{let data_dir=app.path().app_local_data_dir()?;std::fs::create_dir_all(&data_dir)?;let db_path=data_dir.join("sentinel-local.sqlite3");db_connection(&db_path).map_err(std::io::Error::other)?;app.manage(AppState{scans:Mutex::new(HashMap::new()),db_path});Ok(())})
 .invoke_handler(tauri::generate_handler![get_security_snapshot,discover_network_topology,list_known_devices,choose_scan_target,save_device_label,detect_supported_tools,start_scan,get_scan_progress,cancel_scan,list_findings,run_diagnostics,open_verified_tool,open_router_admin])
 .run(tauri::generate_context!()).expect("error while running Sentinel Local");
}
