export const resolverCatalog = {
  auto: {
    id: "auto",
    label: "Auto",
    description: "Uses Google Public DNS by default.",
    servers: [] as string[],
    dohUrl: "https://dns.google/dns-query"
  },
  google: {
    id: "google",
    label: "Google",
    description: "Public DNS by Google.",
    servers: ["8.8.8.8", "8.8.4.4"],
    dohUrl: "https://dns.google/dns-query"
  },
  cloudflare: {
    id: "cloudflare",
    label: "Cloudflare",
    description: "Public DNS by Cloudflare.",
    servers: ["1.1.1.1", "1.0.0.1"],
    dohUrl: "https://cloudflare-dns.com/dns-query"
  },
  quad9: {
    id: "quad9",
    label: "Quad9",
    description: "Public DNS by Quad9.",
    servers: ["9.9.9.9", "149.112.112.112"],
    dohUrl: "https://dns.quad9.net/dns-query"
  },
  opendns: {
    id: "opendns",
    label: "OpenDNS",
    description: "Public DNS by OpenDNS.",
    servers: ["208.67.222.222", "208.67.220.220"],
    dohUrl: "https://dns.opendns.com/dns-query"
  }
} as const;

export type ResolverId = keyof typeof resolverCatalog;

export const recordTypeOptions = [
  { value: "A", label: "A" },
  { value: "AAAA", label: "AAAA" },
  { value: "CNAME", label: "CNAME" },
  { value: "MX", label: "MX" },
  { value: "TXT", label: "TXT" },
  { value: "NS", label: "NS" },
  { value: "SOA", label: "SOA" },
  { value: "PTR", label: "PTR" },
  { value: "CAA", label: "CAA" },
  { value: "SRV", label: "SRV" },
  { value: "DS", label: "DS" },
  { value: "DNSKEY", label: "DNSKEY" },
  { value: "RRSIG", label: "RRSIG" },
  { value: "DMARC", label: "DMARC" },
  { value: "DKIM", label: "DKIM" },
  { value: "SPF", label: "SPF" }
] as const;

export type RecordType = (typeof recordTypeOptions)[number]["value"];

export type DnsAnswer = {
  type: string;
  value: string;
  ttl?: number;
  priority?: number;
  notes?: string;
};

export type DnsResolverResult = {
  resolver: ResolverId;
  resolverLabel: string;
  queryName: string;
  responseTimeMs?: number;
  answers: DnsAnswer[];
  raw: string;
  error?: string;
};

export type DnsLookupRequest = {
  target: string;
  recordType: RecordType;
  resolver: ResolverId;
  compareAll?: boolean;
  shortMode?: boolean;
  raw?: boolean;
  dkimSelector?: string;
};

export type DnsLookupResponse = {
  query: string;
  displayQuery: string;
  effectiveQuery: string;
  recordType: RecordType;
  requestedResolver: ResolverId;
  compareAll: boolean;
  generatedAt: string;
  summary: string;
  results: DnsResolverResult[];
};

export type BulkLookupRow = {
  target: string;
  status: "ok" | "empty" | "error";
  summary: string;
  lookup?: DnsLookupResponse;
  error?: string;
};

export type BulkLookupResponse = {
  generatedAt: string;
  recordType: RecordType;
  resolver: ResolverId;
  compareAll: boolean;
  rows: BulkLookupRow[];
};
