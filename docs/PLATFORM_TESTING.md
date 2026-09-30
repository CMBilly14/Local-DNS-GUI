# Platform builds, testing and signing

One application codebase produces separate packages; there is no need to fork the product for each operating system.

| Platform | Build command (on that OS) | Output | Local validation status |
| --- | --- | --- | --- |
| Windows x64 | `npm run dist:windows` | Portable `.exe` | Built; automated GUI and engine tests run on Windows |
| Linux x64 | `npm run dist:linux` | `.AppImage` | Not yet built/tested on Linux |
| macOS Intel + Apple Silicon | `npm run dist:mac` | `.dmg` and `.zip` per architecture | Not yet built/tested on macOS |

Run `npm ci` first, using Node 22.12+ and npm. Building is not equivalent to testing: the resulting app must run on the target operating system. Neither a macOS nor a Linux package is claimed as verified by a Windows test.

## Test environments

Linux GUI testing requires a Linux desktop, a Linux VM, or WSL 2 with WSLg. WSL networking can differ from native Linux, particularly around VPN routing. macOS testing and signing require a Mac or a macOS runner. Packaging alone does not establish runtime compatibility.

## Reusable GUI regression tests

```sh
npm test
npm run typecheck
npm run lint
npm run test:gui
# After building on Windows:
npm run test:gui -- --packaged
```

The GUI test starts local UDP and TCP fixtures and uses an isolated profile under `test-output/`. It does not alter normal application history. It covers answer/authority/additional tabs, recursive labeling, negative/empty answers, UDP-to-TCP fallback, TCP-only queries, safe TXT rendering, both export formats, validation, timeouts, cancellation, history search and recall, restart persistence, clearing and minimum window size. Save dialogs are stubbed to a test destination: native file-picker interaction still deserves a manual check.

The source test resolves Electron for the current OS. Packaged tests accept `DNS_LOCAL_EXECUTABLE` to identify a different app binary (for example a macOS `mac-arm64` output). The repository CI runs the GUI regression on Windows and macOS directly and on Linux through `xvfb-run`. Do not disable Electron's sandbox merely to make tests pass.

Tagged pushes matching `v*` run the same validation on hosted Windows, Linux, and macOS machines, build the native packages, generate `SHA256SUMS.txt`, and create a prerelease containing those artifacts. The workflow does not sign or notarize the packages.

Tests provide repeatable evidence, not proof across all VPNs, DNS servers, displays or Linux distributions. OS integration, fresh-user installation, accessibility, and target-platform packaging should also be checked before public release.

### Windows verification, 2026-09-28

The final standalone Windows build passed all 20 engine/core tests, typechecking, ESLint and 17 grouped packaged-GUI checks. An initial automated launch timed out at 30 seconds; the rerun passed. The timeout cause remains unconfirmed. Second-machine testing and manual native file-picker checks remain outstanding.

### SPF filtering regression

After correcting SPF answer selection, all 20 engine/core tests and 17 grouped packaged-GUI checks pass. Tests cover unrelated verification TXT records, multiple SPF records, split TXT strings, case-insensitive version markers, rejection of `v=spf10` lookalikes, empty SPF results, SPF-only comparison, and unchanged ordinary TXT searches. The GUI heading retains SPF while the underlying DNS query remains TXT. Full packets are preserved in the raw view.

## Signing

Code signing attaches a cryptographic publisher signature to a build so the OS can verify its signer and detect changes after signing. It does not prove correctness. Windows reputation checks can still warn about a newly signed application. macOS distribution normally uses an Apple Developer ID signature plus notarization, Apple's separate automated malware check. Linux distribution trust depends on the package format and repository; AppImages can run without the same Windows/macOS signing flow.

Signing identities and credentials must be supplied by the owner. They are not generated or purchased automatically. Current Windows builds remain unsigned.

References: [Windows signing and reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation), [Apple Developer ID](https://developer.apple.com/developer-id/), [platform build guidance](https://www.electron.build/docs/features/multi-platform-build/), [Linux GUI apps through WSL](https://learn.microsoft.com/en-us/windows/wsl/tutorials/gui-apps).
