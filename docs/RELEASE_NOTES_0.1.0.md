# DNS Local 0.1.0 Preview

Initial Windows x64 preview of the local desktop DNS inspector.

## Download and run

Download `DNS.Local.0.1.0.exe` from this release and open it. Electron and production dependencies are bundled; Node.js and npm are not required. No installer is required.

This release is intentionally unsigned. Windows may show an Unknown publisher or Windows protected your PC warning, and managed devices may block unsigned applications. Follow your device administrator's policies.

## Features

- Direct UDP/TCP DNS queries, custom nameservers and ports.
- Authoritative lookups, delegation tracing and comparison with public resolver caches.
- SPF-only results; ordinary TXT searches retain all TXT records.
- Raw packet inspection, local query history, cancellation, and JSON/text exports.
- No accounts, telemetry or automatic update checks.

## Validation and limitations

Windows validation passed 20 engine/core tests, typechecking, linting and 17 grouped packaged GUI checks. An initial automated launch timed out; the rerun passed. Testing on a second Windows machine remains outstanding. Native save-dialog interaction and broader OS integration still need manual checks.

macOS and Linux packages are not included or verified. Direct DNS requires access to the selected nameservers; network policies may restrict it. The app does not locally validate DNSSEC chains. See README.md for additional limitations.

## Integrity

`SHA256SUMS.txt` contains the SHA-256 checksum of the executable. On Windows, run:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\DNS.Local.0.1.0.exe'
```

Compare the hash with the checksum file. A checksum detects file differences; it is not a publisher signature.
