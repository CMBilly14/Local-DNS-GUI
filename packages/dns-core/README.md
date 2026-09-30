# DNS Core

Framework-free TypeScript DNS helpers used by DNS Local. MIT licensed.

Includes query preparation, record normalization, resolver catalog, IP/PTR handling and DoH transport. The desktop application supplies raw UDP/TCP transports. Unused RDAP and email-analysis modules are not included.

From the repository root:

```sh
npm ci
npm run build:core
npm test
```

Import compiled ESM subpaths such as `@dns-search/core/dns/lookup`, `@dns-search/core/dns/transport`, and `@dns-search/core/utils/ip`. The package has no React or Next.js imports. Source is in `src/`; TypeScript generates `dist/`.

Deep SPF lookup counting, DKIM key analysis, DMARC policy findings and independent DNSSEC validation are not implemented. The wire codec is the dns-packet dependency. Node 22.12+ is supported.
