import { recordTypeOptions, resolverCatalog, type RecordType, type ResolverId } from "./types.js";
import { isIpAddress } from "../utils/ip.js";

const domainPattern =
  /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const hostnamePattern =
  /^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9_])?$/i;

export function normalizeUserTarget(value: string) {
  return value.trim().replace(/\.$/, "");
}

export function looksLikeIp(value: string) {
  return isIpAddress(normalizeUserTarget(value));
}

export function isProbablyDnsName(value: string) {
  const candidate = normalizeUserTarget(value);
  return domainPattern.test(candidate) || hostnamePattern.test(candidate);
}

export function isTargetAllowed(value: string) {
  const candidate = normalizeUserTarget(value);
  return candidate.length > 0 && (looksLikeIp(candidate) || isProbablyDnsName(candidate));
}

export function coerceResolverId(value: string | undefined): ResolverId {
  if (value && value in resolverCatalog) {
    return value as ResolverId;
  }

  return "auto";
}

export function coerceRecordType(value: string | undefined): RecordType {
  if (value && recordTypeOptions.some((option) => option.value === value.toUpperCase())) {
    return value.toUpperCase() as RecordType;
  }

  return "A";
}

export function coerceBooleanFlag(value: string | undefined) {
  return value === "1" || value === "true" || value === "yes";
}
