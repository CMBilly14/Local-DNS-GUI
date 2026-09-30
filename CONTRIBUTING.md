# Contributing

Use Node.js 22 or newer. Install dependencies and run the desktop app as documented in the README. Before submitting changes, run `npm run typecheck`, `npm run lint`, and `npm test`. Transport and trace behavior should have deterministic fixture tests; tests must not depend on live public DNS.

Keep socket and filesystem access in the main process. Keep the renderer sandboxed, validate IPC input, and render DNS data as text. Never describe a public recursive answer as authoritative. Do not add telemetry or cloud state.

Changes to the engine belong in `packages/dns-core`; keep it framework-free. Build release artifacts on their target operating systems. Do not commit signing keys or credentials.
