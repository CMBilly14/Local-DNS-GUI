export type TransportOptions = { timeoutMs?: number; signal?: AbortSignal };

export interface DnsTransport {
  id: string;
  label: string;
  query(packet: Uint8Array, options?: TransportOptions): Promise<Uint8Array>;
}

/** RFC 8484 transport; no socket or product dependencies. */
export class DohTransport implements DnsTransport {
  readonly id = "doh";
  constructor(public readonly endpoint: string, public readonly label = "DNS over HTTPS") {}
  async query(packet: Uint8Array, options: TransportOptions = {}) {
    const timeout = AbortSignal.timeout(options.timeoutMs ?? 5000);
    const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
    const body = new Uint8Array(packet).buffer;
    const headers = { accept: "application/dns-message", "content-type": "application/dns-message" };
    let response = await fetch(this.endpoint, { method: "POST", headers, body, signal, cache: "no-store" });
    if ([400, 405, 415].includes(response.status)) {
      await response.body?.cancel();
      const url = new URL(this.endpoint);
      let binary = "";
      for (const byte of packet) binary += String.fromCharCode(byte);
      url.searchParams.set("dns", btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
      response = await fetch(url, { headers: { accept: headers.accept }, signal, cache: "no-store" });
    }
    if (!response.ok) throw new Error(`DoH request failed with HTTP ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }
}
