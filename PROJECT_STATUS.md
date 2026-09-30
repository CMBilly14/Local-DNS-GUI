# Project status

DNS Local 0.1.0 is an unsigned Windows x64 preview of the standalone Electron desktop DNS inspector.

## Implemented

- Direct UDP/TCP with truncation fallback and bounded timeouts.
- System, public, custom, authoritative and delegation-trace modes.
- Authoritative-versus-public comparison, SPF-only filtering, raw packet inspection.
- Searchable local history, cancellation, JSON/text export and reproducible dig commands.

## Verification

The Windows build passed 20 engine/core tests and 17 grouped packaged-GUI regression checks, along with typechecking and linting. Live lookups and root-to-authority tracing have also been verified on Windows. Tests use isolated profiles and local DNS fixtures.

## Remaining work

- Testing on a second Windows machine, native save dialogs and broader OS integration.
- Native Linux and macOS build/runtime verification.
- Application signing is intentionally deferred. It is not a prerequisite for publishing this preview. Future macOS distribution may need signing and notarization.
- DNSSEC chain validation, watch mode, saved profiles and a CLI are future features.

See README.md for capabilities and limitations, and docs/PLATFORM_TESTING.md for build and test procedures.
