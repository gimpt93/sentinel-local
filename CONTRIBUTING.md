# Contributing

Sentinel Local is currently maintained as a focused Windows 11 prototype.

Before proposing a change:

- Keep the application local-first and free of telemetry, advertising, subscriptions, and paid recommendations.
- Do not add a generic shell bridge, unrestricted filesystem access, credential storage, or silent packet capture.
- Preserve standard-user startup and explicit consent for scans.
- Treat device identity and vendor information as uncertain observations.
- Keep destructive or privileged remediation simulated unless it has undergone a separate security review.

For code changes, run:

```powershell
npm run lint
npm test
npm run build
Set-Location src-tauri
cargo test
```

Security vulnerabilities should follow [SECURITY.md](SECURITY.md), not the public issue tracker.

