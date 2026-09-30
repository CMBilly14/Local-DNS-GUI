import { Buffer } from "node:buffer";
import dnsPacket from "dns-packet";
import { DohTransport } from "./transport.js";

import {
  resolverCatalog,
  type DnsAnswer,
  type DnsLookupRequest,
  type DnsLookupResponse,
  type DnsResolverResult,
  type RecordType,
  type ResolverId
} from "./types.js";
import { normalizeUserTarget } from "./validators.js";
import { isIpAddress, reversePointerName } from "../utils/ip.js";

type PreparedQuery = {
  queryName: string;
  displayQuery: string;
  underlyingType: Exclude<RecordType, "DMARC" | "DKIM" | "SPF"> | "TXT";
  postFilter?: (answer: DnsAnswer) => boolean;
};

type WireDnsPacket = {
  encode: (value: unknown) => Uint8Array;
  decode: (value: Uint8Array) => {
    answers?: unknown[];
  };
  RECURSION_DESIRED: number;
};

const wireDns = dnsPacket as unknown as WireDnsPacket;
const textDecoder = new TextDecoder();

function resolverForLookup(resolverId: ResolverId) {
  return resolverId === "auto" ? resolverCatalog.google : resolverCatalog[resolverId];
}

export function prepareQuery(target: string, recordType: RecordType, dkimSelector?: string): PreparedQuery {
  const normalizedTarget = normalizeUserTarget(target);

  if (recordType === "DMARC") {
    const queryName = normalizedTarget.startsWith("_dmarc.")
      ? normalizedTarget
      : `_dmarc.${normalizedTarget}`;

    return {
      queryName,
      displayQuery: queryName,
      underlyingType: "TXT",
      postFilter: (answer) => answer.value.toUpperCase().startsWith("V=DMARC1")
    };
  }

  if (recordType === "DKIM") {
    const queryName =
      normalizedTarget.includes("._domainkey.") || !dkimSelector
        ? normalizedTarget
        : `${dkimSelector}._domainkey.${normalizedTarget}`;

    return {
      queryName,
      displayQuery: queryName,
      underlyingType: "TXT"
    };
  }

  if (recordType === "SPF") {
    return {
      queryName: normalizedTarget,
      displayQuery: normalizedTarget,
      underlyingType: "TXT",
      postFilter: (answer) => /^v=spf1(?: |$)/i.test(answer.value)
    };
  }

  if (recordType === "PTR" && isIpAddress(normalizedTarget)) {
    return {
      queryName: reversePointerName(normalizedTarget) ?? normalizedTarget,
      displayQuery: normalizedTarget,
      underlyingType: "PTR"
    };
  }

  return {
    queryName: normalizedTarget,
    displayQuery: normalizedTarget,
    underlyingType: recordType
  };
}

function serializeAnswer(answer: DnsAnswer) {
  return JSON.stringify({
    type: answer.type,
    value: answer.value,
    ttl: answer.ttl ?? null,
    priority: answer.priority ?? null,
    notes: answer.notes ?? null
  });
}

function summarize(response: Omit<DnsLookupResponse, "summary">) {
  const successful = response.results.filter((result) => !result.error);
  const populated = successful.filter((result) => result.answers.length > 0);

  if (response.compareAll) {
    if (!successful.length) {
      return "None of the selected public resolvers returned a successful answer.";
    }

    if (!populated.length) {
      return `The selected resolvers did not return any ${response.recordType} records.`;
    }

    const fingerprints = populated.map((result) =>
      result.answers
        .map((answer) => serializeAnswer(answer))
        .sort()
        .join("|")
    );
    const uniqueFingerprints = new Set(fingerprints);

    if (uniqueFingerprints.size === 1) {
      return `All ${populated.length} resolvers returned the same ${response.recordType} answer set.`;
    }

    return `Resolvers returned different ${response.recordType} answers, which usually points to caching or propagation differences.`;
  }

  const primary = response.results[0];

  if (!primary || primary.error) {
    return `${primary?.resolverLabel ?? "The resolver"} could not complete this lookup.`;
  }

  if (!primary.answers.length) {
    return `${primary.resolverLabel} did not return any ${response.recordType} records.`;
  }

  const plural = primary.answers.length === 1 ? "record" : "records";
  return `${primary.resolverLabel} returned ${primary.answers.length} ${response.recordType} ${plural}.`;
}

function normalizeTxtSegment(value: unknown) {
  if (typeof value === "string") {
    return value;
  }

  if (value instanceof Uint8Array) {
    return textDecoder.decode(value);
  }

  return String(value ?? "");
}

function parseTxtAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const segments = Array.isArray(answer.data) ? answer.data : [answer.data];

  return {
    type: recordType,
    value: segments.map(normalizeTxtSegment).join(""),
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined
  };
}

function parseCaaAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;
  const tag = typeof data?.tag === "string" ? data.tag : "";
  const value = normalizeTxtSegment(data?.value);
  const critical =
    typeof data?.issuerCritical === "boolean"
      ? data.issuerCritical
      : typeof data?.flags === "number"
        ? (data.flags & 0x80) === 0x80
        : false;

  return {
    type: recordType,
    value: `${tag} ${value}`.trim() || "CAA policy present",
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    notes: `critical ${critical}`
  };
}

function parseSoaAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;

  return {
    type: recordType,
    value: `${String(data?.mname ?? "")} ${String(data?.rname ?? "")}`.trim(),
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    notes: `serial ${String(data?.serial ?? "n/a")}, refresh ${String(data?.refresh ?? "n/a")}, retry ${String(data?.retry ?? "n/a")}`
  };
}

function parseSrvAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;

  return {
    type: recordType,
    value: `${String(data?.target ?? "")}:${String(data?.port ?? "")}`,
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    priority: typeof data?.priority === "number" ? data.priority : undefined,
    notes: typeof data?.weight === "number" ? `weight ${data.weight}` : undefined
  };
}

function encodeBinaryValue(value: unknown, format: "base64" | "hex") {
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString(format);
  }

  if (Buffer.isBuffer(value)) {
    return value.toString(format);
  }

  return String(value ?? "");
}

function parseDsAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;
  const digest = encodeBinaryValue(data?.digest, "hex").toUpperCase();

  return {
    type: recordType,
    value: digest,
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    notes: `key tag ${String(data?.keyTag ?? "n/a")}, algorithm ${String(data?.algorithm ?? "n/a")}, digest type ${String(data?.digestType ?? "n/a")}`
  };
}

function parseDnskeyAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;
  const key = encodeBinaryValue(data?.key, "base64");

  return {
    type: recordType,
    value: key,
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    notes: `flags ${String(data?.flags ?? "n/a")}, algorithm ${String(data?.algorithm ?? "n/a")}`
  };
}

function parseRrsigAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;
  const signature = encodeBinaryValue(data?.signature, "base64");
  const typeCovered = String(data?.typeCovered ?? "");
  const signer = String(data?.signersName ?? "");

  return {
    type: recordType,
    value: `${typeCovered}${signer ? ` by ${signer}` : ""}`.trim() || signature,
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    notes: `algorithm ${String(data?.algorithm ?? "n/a")}, key tag ${String(data?.keyTag ?? "n/a")}, labels ${String(data?.labels ?? "n/a")}`
  };
}

function parseMxAnswer(answer: Record<string, unknown>, recordType: RecordType): DnsAnswer {
  const data = answer.data as Record<string, unknown> | undefined;

  return {
    type: recordType,
    value: String(data?.exchange ?? ""),
    ttl: typeof answer.ttl === "number" ? answer.ttl : undefined,
    priority: typeof data?.preference === "number" ? data.preference : undefined
  };
}

export function parseDnsAnswers(packetResponse: { answers?: unknown[] }, recordType: RecordType) {
  const answers = Array.isArray(packetResponse.answers) ? packetResponse.answers : [];

  return answers.flatMap((entry) => {
    if (!entry || typeof entry !== "object") {
      return [];
    }

    const answer = entry as Record<string, unknown>;

    switch (recordType) {
      case "A":
      case "AAAA":
      case "CNAME":
      case "NS":
      case "PTR":
        return [
          {
            type: recordType,
            value: String(answer.data ?? ""),
            ttl: typeof answer.ttl === "number" ? answer.ttl : undefined
          }
        ];
      case "MX":
        return [parseMxAnswer(answer, recordType)];
      case "TXT":
      case "SPF":
      case "DMARC":
      case "DKIM":
        return [parseTxtAnswer(answer, recordType)];
      case "SOA":
        return [parseSoaAnswer(answer, recordType)];
      case "CAA":
        return [parseCaaAnswer(answer, recordType)];
      case "SRV":
        return [parseSrvAnswer(answer, recordType)];
      case "DS":
        return [parseDsAnswer(answer, recordType)];
      case "DNSKEY":
        return [parseDnskeyAnswer(answer, recordType)];
      case "RRSIG":
        return [parseRrsigAnswer(answer, recordType)];
      default:
        return [];
    }
  });
}

function buildDnsQuery(queryName: string, recordType: PreparedQuery["underlyingType"]) {
  const id = crypto.getRandomValues(new Uint16Array(1))[0];

  return new Uint8Array(
    wireDns.encode({
      type: "query",
      id,
      flags: wireDns.RECURSION_DESIRED,
      questions: [
        {
          type: recordType,
          name: queryName
        }
      ]
    })
  );
}

async function lookupWithResolver(
  resolverId: ResolverId,
  target: string,
  recordType: RecordType,
  dkimSelector?: string
): Promise<Omit<DnsResolverResult, "resolverLabel"> & { resolverLabel: string }> {
  const resolver = resolverForLookup(resolverId);
  const prepared = prepareQuery(target, recordType, dkimSelector);
  const startedAt = performance.now();

  try {
    const payload = buildDnsQuery(prepared.queryName, prepared.underlyingType);
    const rawPacket = await new DohTransport(resolver.dohUrl).query(payload);
    let answers = parseDnsAnswers(wireDns.decode(Buffer.from(rawPacket)), recordType);

    if (prepared.postFilter) {
      answers = answers.filter(prepared.postFilter);
    }

    const responseTimeMs = Math.round(performance.now() - startedAt);

    return {
      resolver: resolverId,
      resolverLabel: resolver.label,
      queryName: prepared.queryName,
      responseTimeMs,
      answers,
      raw: JSON.stringify(
        {
          resolver: resolver.label,
          query: prepared.queryName,
          recordType,
          answers
        },
        null,
        2
      )
    };
  } catch (error) {
    const responseTimeMs = Math.round(performance.now() - startedAt);

    return {
      resolver: resolverId,
      resolverLabel: resolver.label,
      queryName: prepared.queryName,
      responseTimeMs,
      answers: [],
      raw: "",
      error: error instanceof Error ? error.message : "Unknown lookup error"
    };
  }
}

export async function performDnsLookup(request: DnsLookupRequest): Promise<DnsLookupResponse> {
  const normalizedTarget = normalizeUserTarget(request.target);
  const prepared = prepareQuery(normalizedTarget, request.recordType, request.dkimSelector);
  const resolverIds: ResolverId[] =
    request.compareAll && request.resolver !== "auto"
      ? ["google", "cloudflare", "quad9", "opendns"]
      : request.compareAll
        ? ["google", "cloudflare", "quad9", "opendns"]
        : [request.resolver];

  const results = await Promise.all(
    resolverIds.map((resolverId) =>
      lookupWithResolver(resolverId, normalizedTarget, request.recordType, request.dkimSelector)
    )
  );

  const responseWithoutSummary = {
    query: normalizedTarget,
    displayQuery: normalizedTarget,
    effectiveQuery: prepared.displayQuery,
    recordType: request.recordType,
    requestedResolver: request.resolver,
    compareAll: Boolean(request.compareAll),
    generatedAt: new Date().toISOString(),
    results
  };

  return {
    ...responseWithoutSummary,
    summary: summarize(responseWithoutSummary)
  };
}
