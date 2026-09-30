import ipaddr from "ipaddr.js";

function normalizeCandidate(value: string) {
  return value.trim().replace(/^\[|\]$/g, "");
}

export function parseIpAddress(value: string) {
  const candidate = normalizeCandidate(value);

  try {
    return ipaddr.parse(candidate);
  } catch {
    return null;
  }
}

export function isIpAddress(value: string) {
  return parseIpAddress(value) !== null;
}

export function reversePointerName(value: string) {
  const parsed = parseIpAddress(value);

  if (!parsed) {
    return null;
  }

  if (parsed.kind() === "ipv4") {
    return parsed.toByteArray().slice().reverse().join(".") + ".in-addr.arpa";
  }

  const expanded = parsed.toByteArray().map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return expanded.split("").reverse().join(".") + ".ip6.arpa";
}
