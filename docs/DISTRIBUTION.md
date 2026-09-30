# Distribution

## Windows users

The portable `DNS Local 0.1.0.exe` release asset includes the application, Electron runtime, DNS engine and required production dependencies. Windows x64 users can run that single executable without installing Node.js, npm, or any packages.

The portable executable extracts its runtime to a temporary directory when opened. Application history is stored in the user's application-data folder. DNS queries need network access to the selected nameservers. The current Windows release is intentionally unsigned. Code signing is deferred and may be added to a future release. Windows may display an "Unknown publisher" or "Windows protected your PC" warning; organizational security policies may block unsigned applications. Follow your device administrator's policies. Publishing the source repository does not require application signing.

## Source repository

Source users need Node.js 22.12+ and npm. Run `npm ci`, then `npm start`. The committed lockfile specifies dependencies; npm downloads them. Do not commit `node_modules`, generated `dist` output, test profiles, caches or logs.

The source tree, tests, configuration, documentation, screenshot and license files belong in Git. The `release` folder is intentionally ignored. Attach the Windows executable to a GitHub Release separately when ready to publish it. No extra dependency archive is required for packaged-app users.

## Other operating systems

Linux and macOS need their own platform-specific packages. Build commands are in `PLATFORM_TESTING.md`. Those packages are not included or claimed as tested in this distribution.
