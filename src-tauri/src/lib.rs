use chrono::{DateTime, Local, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
};
use tauri::{Manager, State};

#[derive(Clone, Serialize)]
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceProfile {
    id: String,
    name: String,
    #[serde(rename = "type")]
    device_type: String,
    ip: String,
    mac: String,
    vendor: Option<String>,
    trust: String,
    access: String,
    first_seen: String,
    last_seen: String,
    discovery_source: String,
    risk_reasons: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkTopology {
    gateway: String,
    lan_prefix: String,
    adapter: String,
    devices: Vec<DeviceProfile>,
    observed_at: DateTime<Utc>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolStatus {
    id: String,
    name: String,
    installed: bool,
    version: Option<String>,
    capability: String,
    state: String,
    official_url: String,
    open_source: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanRequest {
    scan_type: String,
    engine: String,
    targets: Vec<String>,
    exclusions: Vec<String>,
    consent_timestamp: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgress {
    id: String,
    state: String,
    percent: u8,
    message: String,
    started_at: DateTime<Utc>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatFinding {
    id: String,
    engine: String,
    classification: String,
    confidence: String,
    location: String,
    sha256: String,
    detected_at: DateTime<Utc>,
    severity: String,
    available_actions: Vec<String>,
    simulated_state: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticResult {
    id: String,
    check: String,
    severity: String,
    evidence: String,
    recommendation: String,
    elevation_required: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    title: String,
    detail: String,
    time: String,
}

struct ScanRecord {
    progress: ScanProgress,
    child: Option<Child>,
    engine: String,
    output_path: Option<PathBuf>,
    target: Option<PathBuf>,
}
struct AppState {
    scans: Mutex<HashMap<String, ScanRecord>>,
    findings: Mutex<Vec<ThreatFinding>>,
    db_path: PathBuf,
    scan_dir: PathBuf,
}

trait NoWindow {
    fn no_window(&mut self) -> &mut Self;
}
impl NoWindow for Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            self.creation_flags(0x08000000);
        }
        self
    }
}
fn run_ps(script: &str) -> Option<String> {
    Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Restricted",
            "-Command",
            script,
        ])
        .no_window()
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
fn ps_bool(script: &str) -> Option<bool> {
    run_ps(script).and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}
fn db(path: &Path) -> Result<Connection, String> {
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS device_labels(id TEXT PRIMARY KEY,label TEXT NOT NULL,trust TEXT NOT NULL,updated_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS event_log(id INTEGER PRIMARY KEY AUTOINCREMENT,event_type TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL,created_at TEXT NOT NULL);").map_err(|e|e.to_string())?;
    Ok(c)
}
fn record_event(path: &Path, event_type: &str, title: &str, detail: &str) {
    if let Ok(c) = db(path) {
        let _ = c.execute(
            "INSERT INTO event_log(event_type,title,detail,created_at) VALUES(?1,?2,?3,?4)",
            params![event_type, title, detail, Utc::now().to_rfc3339()],
        );
    }
}
fn private_ipv4(v: &str) -> bool {
    v.parse::<Ipv4Addr>()
        .map(|ip| ip.is_private())
        .unwrap_or(false)
}
fn gateway() -> Option<String> {
    run_ps("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object NextHop -ne '0.0.0.0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)").filter(|v|private_ipv4(v))
}
fn local_ip() -> Option<String> {
    run_ps("Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } | Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty IPAddress").filter(|v|private_ipv4(v))
}
fn stable_id(mac: &str, ip: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{mac}|{ip}").as_bytes());
    format!("neighbor-{}", &format!("{:x}", h.finalize())[..16])
}
fn labels(path: &Path) -> HashMap<String, (String, String)> {
    let Ok(c) = db(path) else {
        return HashMap::new();
    };
    let Ok(mut s) = c.prepare("SELECT id,label,trust FROM device_labels") else {
        return HashMap::new();
    };
    s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|(id, l, t)| (id, (l, t)))
        .collect()
}

fn devices(db_path: &Path, gw: Option<&str>) -> Vec<DeviceProfile> {
    let known = labels(db_path);
    let mut out = Vec::new();
    if let Some(ip) = local_ip() {
        out.push(DeviceProfile {
            id: "this-pc".into(),
            name: "This PC (You)".into(),
            device_type: "pc".into(),
            ip,
            mac: "Local device".into(),
            vendor: None,
            trust: "trusted".into(),
            access: "Full".into(),
            first_seen: "Local system".into(),
            last_seen: "Now".into(),
            discovery_source: "Windows IP configuration".into(),
            risk_reasons: vec![],
        });
    }
    if let Some(ip) = gw {
        out.push(DeviceProfile {
            id: "router".into(),
            name: "Home router".into(),
            device_type: "router".into(),
            ip: ip.into(),
            mac: "Gateway".into(),
            vendor: None,
            trust: "trusted".into(),
            access: "Network control".into(),
            first_seen: "Current route".into(),
            last_seen: "Now".into(),
            discovery_source: "Windows default route".into(),
            risk_reasons: vec![],
        });
    }
    if let Ok(o) = Command::new("arp.exe").arg("-a").no_window().output() {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() < 3
                || !private_ipv4(p[0])
                || gw == Some(p[0])
                || out.iter().any(|d| d.ip == p[0])
            {
                continue;
            }
            let mac = p[1].to_ascii_uppercase();
            if mac == "FF-FF-FF-FF-FF-FF" || mac.starts_with("01-00-5E") {
                continue;
            }
            let id = stable_id(&mac, p[0]);
            let (name, trust) = known
                .get(&id)
                .cloned()
                .unwrap_or(("Unidentified device".into(), "unknown".into()));
            out.push(DeviceProfile {
                id,
                name,
                device_type: "unknown".into(),
                ip: p[0].into(),
                mac,
                vendor: None,
                trust: trust.clone(),
                access: "Router managed".into(),
                first_seen: "Observed locally".into(),
                last_seen: "Current neighbor cache".into(),
                discovery_source: "Windows ARP neighbor table".into(),
                risk_reasons: if trust == "unknown" {
                    vec!["This device has not been labeled on this PC".into()]
                } else {
                    vec![]
                },
            })
        }
    }
    out.truncate(32);
    out
}

fn clam_age() -> Option<u32> {
    [
        r"C:\Program Files\ClamAV\database\daily.cvd",
        r"C:\Program Files\ClamAV\database\daily.cld",
        r"C:\ClamAV\database\daily.cvd",
    ]
    .iter()
    .filter_map(|p| fs::metadata(p).ok()?.modified().ok())
    .max()
    .and_then(|t| t.elapsed().ok())
    .map(|a| (a.as_secs() / 86400) as u32)
}
#[tauri::command]
fn get_security_snapshot() -> SecuritySnapshot {
    let defender =
        ps_bool("[bool](Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled")
            .unwrap_or(false);
    let firewall=ps_bool("[bool]((Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object Enabled -eq $false).Count -eq 0)").unwrap_or(false);
    let hotfix=run_ps("Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn");
    let updates = hotfix
        .as_deref()
        .and_then(|v| chrono::NaiveDate::parse_from_str(v, "%m/%d/%Y").ok())
        .map(|d| (Local::now().date_naive() - d).num_days() <= 45)
        .unwrap_or(false);
    let vpn=run_ps("Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Proton|WireGuard|OpenVPN|VPN') } | Select-Object -First 1 -ExpandProperty Name").unwrap_or_default();
    let network=run_ps("Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object IPv4Connectivity -ne 'Disconnected' | Select-Object -First 1 -ExpandProperty Name").filter(|v|!v.is_empty()).unwrap_or("No active network detected".into());
    let connected = !vpn.is_empty();
    let overall = if !defender || !firewall {
        "at_risk"
    } else if !updates {
        "needs_review"
    } else {
        "protected"
    };
    SecuritySnapshot {
        overall: overall.into(),
        defender,
        firewall,
        updates_current: updates,
        vpn_connected: connected,
        vpn_name: if connected {
            vpn
        } else {
            "No VPN adapter detected".into()
        },
        network_name: network,
        clam_definitions_age_days: clam_age(),
        observed_at: Utc::now(),
    }
}
#[tauri::command]
fn discover_network_topology(state: State<AppState>) -> NetworkTopology {
    let gw = gateway();
    let adapter=run_ps("Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty Name").filter(|v|!v.is_empty()).unwrap_or("No active adapter".into());
    let prefix = gw
        .as_deref()
        .and_then(|v| v.rsplit_once('.').map(|(p, _)| format!("{p}.0/24")))
        .unwrap_or("Unavailable".into());
    NetworkTopology {
        devices: devices(&state.db_path, gw.as_deref()),
        gateway: gw.unwrap_or("Unavailable".into()),
        lan_prefix: prefix,
        adapter,
        observed_at: Utc::now(),
    }
}
#[tauri::command]
fn list_known_devices(state: State<AppState>) -> Vec<DeviceProfile> {
    let gw = gateway();
    devices(&state.db_path, gw.as_deref())
}
#[tauri::command]
fn save_device_label(
    state: State<AppState>,
    id: String,
    label: String,
    trust: String,
) -> Result<DeviceProfile, String> {
    if id.len() > 128
        || label.trim().is_empty()
        || label.len() > 80
        || !["trusted", "unknown", "restricted"].contains(&trust.as_str())
    {
        return Err("Invalid local device label".into());
    }
    let current = list_known_devices(state.clone())
        .into_iter()
        .find(|d| d.id == id)
        .ok_or("Device is not currently observed")?;
    db(&state.db_path)?.execute("INSERT INTO device_labels(id,label,trust,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET label=excluded.label,trust=excluded.trust,updated_at=excluded.updated_at",params![id,label,trust,Utc::now().to_rfc3339()]).map_err(|e|e.to_string())?;
    record_event(
        &state.db_path,
        "device",
        "Device label updated",
        "Stored locally",
    );
    Ok(DeviceProfile {
        name: label,
        trust,
        risk_reasons: vec![],
        ..current
    })
}

fn tool_path(id: &str) -> Option<&'static str> {
    let c: &[&str] = match id {
        "clamav" => &[
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\ClamAV\clamscan.exe",
        ],
        "simplewall" => &[
            r"C:\Program Files\simplewall\simplewall.exe",
            r"C:\Program Files (x86)\simplewall\simplewall.exe",
        ],
        "proton" => &[
            r"C:\Program Files\Proton\VPN\ProtonVPN.exe",
            r"C:\Program Files\Proton\VPN\Proton.Vpn.exe",
        ],
        "wireshark" => &[r"C:\Program Files\Wireshark\Wireshark.exe"],
        "nmap" => &[
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        ],
        _ => &[],
    };
    c.iter().copied().find(|p| Path::new(p).is_file())
}
fn version(path: &str) -> Option<String> {
    Command::new(path)
        .arg("--version")
        .no_window()
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|t| t.lines().next().map(|l| l.chars().take(80).collect()))
}
#[tauri::command]
fn detect_supported_tools() -> Vec<ToolStatus> {
    let mut out = vec![ToolStatus {
        id: "defender".into(),
        name: "Windows Security".into(),
        installed: true,
        version: None,
        capability: "Real-time protection".into(),
        state: if get_security_snapshot().defender {
            "Active"
        } else {
            "Needs review"
        }
        .into(),
        official_url: "ms-settings:windowsdefender".into(),
        open_source: false,
    }];
    for (id, name, cap, url) in [
        (
            "clamav",
            "ClamAV (on-demand)",
            "Manual malware scanning",
            "https://www.clamav.net/downloads",
        ),
        (
            "simplewall",
            "simplewall (WFP)",
            "Windows Filtering Platform control",
            "https://github.com/henrypp/simplewall/releases",
        ),
        (
            "proton",
            "Proton VPN Free",
            "VPN connection",
            "https://protonvpn.com/download-windows",
        ),
        (
            "wireshark",
            "Wireshark",
            "Advanced packet analysis",
            "https://www.wireshark.org/download.html",
        ),
        (
            "nmap",
            "Nmap",
            "Private LAN discovery",
            "https://nmap.org/download.html",
        ),
    ] {
        let p = tool_path(id);
        out.push(ToolStatus {
            id: id.into(),
            name: name.into(),
            installed: p.is_some(),
            version: p.and_then(version),
            capability: cap.into(),
            state: if p.is_some() {
                "Detected"
            } else {
                "Not detected"
            }
            .into(),
            official_url: url.into(),
            open_source: true,
        })
    }
    out.push(ToolStatus {
        id: "ublock".into(),
        name: "uBlock Origin".into(),
        installed: false,
        version: None,
        capability: "Browser content filtering".into(),
        state: "Browser-managed; not inspected".into(),
        official_url: "https://github.com/gorhill/uBlock".into(),
        open_source: true,
    });
    out
}
#[tauri::command]
fn choose_scan_target() -> Option<String> {
    let s="Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='Choose a file for an on-demand scan'; $d.CheckFileExists=$true; if($d.ShowDialog() -eq 'OK'){ $d.FileName }";
    Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-STA",
            "-NonInteractive",
            "-Command",
            s,
        ])
        .no_window()
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|v| !v.is_empty())
}
fn user_file(v: &str) -> Result<PathBuf, String> {
    let p = Path::new(v)
        .canonicalize()
        .map_err(|_| "Selected file is not accessible")?;
    let profile = std::env::var("USERPROFILE").map_err(|_| "User profile is unavailable")?;
    if !p.starts_with(Path::new(&profile)) || !p.is_file() {
        return Err("Scan target must be a file in the current user profile".into());
    }
    Ok(p)
}

#[tauri::command]
fn start_scan(state: State<AppState>, request: ScanRequest) -> Result<ScanProgress, String> {
    if !["smart", "quick", "full", "file", "network"].contains(&request.scan_type.as_str())
        || !["defender", "clamav", "local"].contains(&request.engine.as_str())
    {
        return Err("Unsupported scan request".into());
    }
    if request.targets.len() > 1
        || !request.exclusions.is_empty()
        || DateTime::parse_from_rfc3339(&request.consent_timestamp).is_err()
    {
        return Err("Invalid scan input".into());
    }
    let id = format!("scan-{}", Utc::now().timestamp_millis());
    let mut progress = ScanProgress {
        id: id.clone(),
        state: "running".into(),
        percent: 1,
        message: "Starting local scan".into(),
        started_at: Utc::now(),
    };
    let (mut child, mut output, mut target) = (None, None, None);
    match request.engine.as_str() {
        "defender" => {
            let kind = if request.scan_type == "full" {
                "FullScan"
            } else {
                "QuickScan"
            };
            let script = format!("Start-MpScan -ScanType {kind}");
            child = Some(
                Command::new("powershell.exe")
                    .args([
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Restricted",
                        "-Command",
                        &script,
                    ])
                    .no_window()
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|_| "Windows Security scan could not start")?,
            );
            progress.message = format!(
                "Windows Security {} scan running",
                if kind == "FullScan" { "full" } else { "quick" }
            );
        }
        "clamav" => {
            let exe = tool_path("clamav").ok_or("ClamAV is not installed")?;
            let p = user_file(request.targets.first().ok_or("Choose one file to scan")?)?;
            let log = state.scan_dir.join(format!("{id}.log"));
            let stdout = File::create(&log).map_err(|_| "Could not create private scan output")?;
            let stderr = stdout
                .try_clone()
                .map_err(|_| "Could not prepare scan output")?;
            child = Some(
                Command::new(exe)
                    .args(["--infected", "--no-summary"])
                    .arg(&p)
                    .no_window()
                    .stdout(stdout)
                    .stderr(stderr)
                    .spawn()
                    .map_err(|_| "ClamAV scan could not start")?,
            );
            output = Some(log);
            target = Some(p);
            progress.message = "ClamAV on-demand scan running".into();
        }
        _ => {
            let _ = get_security_snapshot();
            let gw = gateway();
            let _ = devices(&state.db_path, gw.as_deref());
            progress.state = "complete".into();
            progress.percent = 100;
            progress.message = "Live local security checks completed".into();
        }
    }
    record_event(
        &state.db_path,
        "scan",
        "Scan started",
        &format!("{} via {}", request.scan_type, request.engine),
    );
    state
        .scans
        .lock()
        .map_err(|_| "Scan state unavailable")?
        .insert(
            id,
            ScanRecord {
                progress: progress.clone(),
                child,
                engine: request.engine,
                output_path: output,
                target,
            },
        );
    Ok(progress)
}
fn file_hash(path: &Path) -> String {
    let Ok(mut f) = File::open(path) else {
        return "Unavailable".into();
    };
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    loop {
        match f.read(&mut b) {
            Ok(0) => break,
            Ok(n) => h.update(&b[..n]),
            Err(_) => return "Unavailable".into(),
        }
    }
    format!("{:x}", h.finalize())
}
fn clam_findings(r: &ScanRecord) -> Vec<ThreatFinding> {
    let (Some(log), Some(target)) = (&r.output_path, &r.target) else {
        return vec![];
    };
    let Ok(text) = fs::read_to_string(log) else {
        return vec![];
    };
    text.lines()
        .filter_map(|line| {
            let found = line.strip_suffix(" FOUND")?;
            let (location, class) = found.rsplit_once(": ")?;
            if target.to_string_lossy() != location {
                return None;
            }
            let hash = file_hash(target);
            Some(ThreatFinding {
                id: format!("clam-{}", &hash[..16.min(hash.len())]),
                engine: "ClamAV".into(),
                classification: class.into(),
                confidence: "Engine detection".into(),
                location: target
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Selected file")
                    .into(),
                sha256: hash,
                detected_at: Utc::now(),
                severity: "high".into(),
                available_actions: vec!["Review in source tool".into()],
                simulated_state: None,
            })
        })
        .collect()
}
#[tauri::command]
fn get_scan_progress(state: State<AppState>, id: String) -> Result<ScanProgress, String> {
    let mut scans = state.scans.lock().map_err(|_| "Scan state unavailable")?;
    let r = scans.get_mut(&id).ok_or("Unknown scan")?;
    if r.progress.state != "running" {
        return Ok(r.progress.clone());
    }
    let finished = match r.child.as_mut() {
        Some(c) => c.try_wait().map_err(|_| "Could not read scanner status")?,
        None => None,
    };
    if let Some(status) = finished {
        r.progress.percent = 100;
        r.progress.state =
            if status.success() || (r.engine == "clamav" && status.code() == Some(1)) {
                "complete"
            } else {
                "failed"
            }
            .into();
        r.progress.message = if r.progress.state == "complete" {
            "Scan completed; live findings refreshed"
        } else {
            "Scanner reported an error; review the source tool"
        }
        .into();
        if r.engine == "clamav" {
            let f = clam_findings(r);
            if !f.is_empty() {
                state
                    .findings
                    .lock()
                    .map_err(|_| "Finding state unavailable")?
                    .extend(f)
            }
        }
        record_event(&state.db_path, "scan", "Scan completed", &r.progress.state);
    } else {
        let elapsed = (Utc::now() - r.progress.started_at).num_seconds().max(0) as u8;
        r.progress.percent = (5 + elapsed / 3).min(90)
    }
    Ok(r.progress.clone())
}
#[tauri::command]
fn cancel_scan(state: State<AppState>, id: String) -> Result<ScanProgress, String> {
    let mut scans = state.scans.lock().map_err(|_| "Scan state unavailable")?;
    let r = scans.get_mut(&id).ok_or("Unknown scan")?;
    if r.engine == "clamav" {
        if let Some(c) = r.child.as_mut() {
            let _ = c.kill();
        }
        r.progress.message = "ClamAV scan cancelled".into()
    } else {
        r.progress.message =
            "Progress tracking stopped. Manage Defender in Windows Security.".into()
    }
    r.progress.state = "cancelled".into();
    record_event(&state.db_path, "scan", "Scan tracking stopped", &r.engine);
    Ok(r.progress.clone())
}

fn defender_findings() -> Vec<ThreatFinding> {
    let s="$items=Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 50; foreach($i in $items){ $name=(Get-MpThreatCatalog -ThreatID $i.ThreatID -ErrorAction SilentlyContinue).ThreatName; $resource=($i.Resources | Select-Object -First 1); Write-Output ($i.ThreatID.ToString()+'|'+$name+'|'+$i.InitialDetectionTime.ToUniversalTime().ToString('o')+'|'+$resource) }";
    run_ps(s)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.splitn(4, '|').collect();
            if f.len() != 4 {
                return None;
            }
            let at = DateTime::parse_from_rfc3339(f[2]).ok()?.with_timezone(&Utc);
            let loc = f[3]
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("Protected resource")
                .trim()
                .into();
            Some(ThreatFinding {
                id: format!("defender-{}-{}", f[0], at.timestamp()),
                engine: "Microsoft Defender".into(),
                classification: if f[1].is_empty() {
                    format!("Threat {}", f[0])
                } else {
                    f[1].into()
                },
                confidence: "Windows Security detection".into(),
                location: loc,
                sha256: "Managed by Windows Security".into(),
                detected_at: at,
                severity: "high".into(),
                available_actions: vec!["Open Windows Security".into()],
                simulated_state: None,
            })
        })
        .collect()
}
#[tauri::command]
fn list_findings(state: State<AppState>) -> Vec<ThreatFinding> {
    let mut f = defender_findings();
    if let Ok(local) = state.findings.lock() {
        f.extend(local.clone())
    }
    f.sort_by_key(|finding| std::cmp::Reverse(finding.detected_at));
    f.dedup_by(|a, b| a.id == b.id);
    f
}
#[tauri::command]
fn list_activity_events(state: State<AppState>) -> Vec<ActivityEvent> {
    let Ok(c) = db(&state.db_path) else {
        return vec![];
    };
    let Ok(mut s) = c.prepare(
        "SELECT id,event_type,title,detail,created_at FROM event_log ORDER BY id DESC LIMIT 50",
    ) else {
        return vec![];
    };
    s.query_map([], |r| {
        let stamp: String = r.get(4)?;
        let time = DateTime::parse_from_rfc3339(&stamp)
            .map(|v| v.with_timezone(&Local).format("%-I:%M %p").to_string())
            .unwrap_or("Recorded".into());
        Ok(ActivityEvent {
            id: r.get::<_, i64>(0)?.to_string(),
            event_type: r.get(1)?,
            title: r.get(2)?,
            detail: r.get(3)?,
            time,
        })
    })
    .ok()
    .into_iter()
    .flatten()
    .filter_map(Result::ok)
    .collect()
}
#[tauri::command]
fn run_diagnostics() -> Vec<DiagnosticResult> {
    let s = get_security_snapshot();
    let gw = gateway();
    vec![
        DiagnosticResult {
            id: "defender".into(),
            check: "Windows Security".into(),
            severity: if s.defender { "good" } else { "risk" }.into(),
            evidence: if s.defender {
                "Microsoft Defender reports active antivirus protection."
            } else {
                "Active Defender protection could not be confirmed."
            }
            .into(),
            recommendation: "Review Windows Security if unexpected.".into(),
            elevation_required: false,
        },
        DiagnosticResult {
            id: "firewall".into(),
            check: "Firewall profiles".into(),
            severity: if s.firewall { "good" } else { "risk" }.into(),
            evidence: if s.firewall {
                "Windows firewall profiles report enabled."
            } else {
                "Enabled firewall profiles could not be confirmed."
            }
            .into(),
            recommendation: "Review firewall profiles in Windows Security.".into(),
            elevation_required: false,
        },
        DiagnosticResult {
            id: "updates".into(),
            check: "Windows update recency".into(),
            severity: if s.updates_current { "good" } else { "review" }.into(),
            evidence: if s.updates_current {
                "A Windows hotfix was installed within 45 days."
            } else {
                "A recent Windows hotfix could not be confirmed."
            }
            .into(),
            recommendation: "Open Windows Update and check for updates.".into(),
            elevation_required: false,
        },
        DiagnosticResult {
            id: "gateway".into(),
            check: "Private gateway".into(),
            severity: if gw.is_some() { "good" } else { "review" }.into(),
            evidence: gw
                .map(|v| format!("Private default gateway detected at {v}."))
                .unwrap_or("No private IPv4 gateway detected.".into()),
            recommendation: "Review the active adapter if connectivity is failing.".into(),
            elevation_required: false,
        },
        DiagnosticResult {
            id: "vpn".into(),
            check: "VPN adapter".into(),
            severity: if s.vpn_connected { "good" } else { "review" }.into(),
            evidence: if s.vpn_connected {
                format!("Active VPN-like adapter detected: {}.", s.vpn_name)
            } else {
                "No active VPN-like adapter detected.".into()
            },
            recommendation: "Open your VPN app if a protected route is expected.".into(),
            elevation_required: false,
        },
    ]
}
fn destination(id: &str) -> Option<&'static str> {
    match id {
        "defender" => Some("ms-settings:windowsdefender"),
        "clamav" => Some("https://www.clamav.net/downloads"),
        "simplewall" => Some("https://github.com/henrypp/simplewall/releases"),
        "proton" => Some("https://protonvpn.com/download-windows"),
        "ublock" => Some("https://github.com/gorhill/uBlock"),
        "wireshark" => Some("https://www.wireshark.org/download.html"),
        "nmap" => Some("https://nmap.org/download.html"),
        _ => None,
    }
}
#[tauri::command]
fn open_verified_tool(tool_id: String) -> Result<bool, String> {
    if let Some(p) = tool_path(&tool_id) {
        Command::new(p)
            .no_window()
            .spawn()
            .map_err(|_| "Could not open detected tool")?;
        return Ok(true);
    }
    let target = destination(&tool_id).ok_or("Unknown tool")?;
    Command::new("explorer.exe")
        .arg(target)
        .no_window()
        .spawn()
        .map_err(|_| "Could not open verified destination")?;
    Ok(true)
}
#[tauri::command]
fn open_router_admin(value: String) -> Result<bool, String> {
    let detected = gateway().ok_or("No private gateway is available")?;
    if !private_ipv4(&value) || value != detected {
        return Err("Router target must match the detected private gateway".into());
    }
    Command::new("explorer.exe")
        .arg(format!("http://{value}"))
        .no_window()
        .spawn()
        .map_err(|_| "Could not open router interface")?;
    Ok(true)
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_local_data_dir()?;
            let scan_dir = dir.join("scan-output");
            fs::create_dir_all(&scan_dir)?;
            let db_path = dir.join("sentinel-local.sqlite3");
            db(&db_path).map_err(std::io::Error::other)?;
            app.manage(AppState {
                scans: Mutex::new(HashMap::new()),
                findings: Mutex::new(Vec::new()),
                db_path,
                scan_dir,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_security_snapshot,
            discover_network_topology,
            list_known_devices,
            save_device_label,
            detect_supported_tools,
            choose_scan_target,
            start_scan,
            get_scan_progress,
            cancel_scan,
            list_findings,
            list_activity_events,
            run_diagnostics,
            open_verified_tool,
            open_router_admin
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel Local");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_targets_must_be_private_ipv4_addresses() {
        assert!(private_ipv4("192.168.1.1"));
        assert!(private_ipv4("10.20.30.1"));
        assert!(!private_ipv4("8.8.8.8"));
        assert!(!private_ipv4("https://example.com"));
    }

    #[test]
    fn external_destinations_are_allowlisted() {
        assert!(destination("clamav")
            .unwrap()
            .starts_with("https://www.clamav.net/"));
        assert!(destination("unknown-tool").is_none());
    }
}
