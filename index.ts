// TypeScript client for lazynton (axum E2EE middleware), built on the
// lazyxchacha npm package (XChaCha20-Poly1305 + X25519, WebAssembly).
// Wire format: application/octet-stream body = raw nonce(24) || ciphertext+tag
// — produced and consumed directly by lazyxchacha's raw byte API, so the
// payload never round-trips through a hex string.

import initWasm, {
  decrypt_raw,
  encrypt_raw,
  from_hex,
  new_keypair,
  shared_key,
  to_hex,
} from "lazyxchacha";

const MIN_WIRE_LEN = 24 + 16; // nonce + poly1305 tag
const KEY_HEX = /^[0-9a-fA-F]{64}$/;

let wasmReady: Promise<void> | undefined;

/** Wait for the WebAssembly module to be usable.
 *
 * lazyxchacha ships two builds. The node one instantiates at import time and
 * exports no initialiser, so this resolves immediately. The browser one fetches
 * its `.wasm` and must be initialised before any export touches wasm memory —
 * that is what the default import is.
 *
 * Every async method here awaits it already, so callers of `E2eeSession`,
 * `wrapFetch`, `attachAxios` and `LazyntonClient` never need to. Await it once
 * before reaching for the synchronous helpers (`encryptBytes`, `decryptBytes`,
 * `encryptToBinary`, `decryptFromBinary`) in a browser. Idempotent and
 * concurrency-safe: every caller shares one initialisation. */
export function ready(): Promise<void> {
  wasmReady ??=
    typeof initWasm === "function"
      ? Promise.resolve(initWasm()).then(() => undefined)
      : Promise.resolve();
  return wasmReady;
}

// Binary handshake frame, mirroring lazynton-rs:
// session_id(16) || server_public_key(32) || expires_in_secs(u32 big-endian).
const SESSION_ID_LEN = 16;
const PUBLIC_KEY_LEN = 32;
const HANDSHAKE_RESPONSE_LEN = SESSION_ID_LEN + PUBLIC_KEY_LEN + 4;

/** Statuses a server predating the binary handshake answers it with; anything
 * else (401, 5xx) is a real failure and must not be retried as JSON. */
const LEGACY_HANDSHAKE_STATUS = new Set([400, 404, 405, 415]);

/** lazynton's documented wire errors. axum answers them with a bare status and
 * no body, so spell out what each one means at the call site. */
const WIRE_ERRORS: Record<number, string> = {
  400: "server could not decrypt the request body (key mismatch)",
  401: "unknown or expired session",
  413: "request exceeds the server's max_body_bytes (default 64 KB)",
  415: "server expected content-type: application/octet-stream",
  503: "server session table is full",
};

// Reused across calls — allocating a coder per call costs more than the
// encoding itself on small payloads.
const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

/** Encrypt raw bytes to lazynton wire bytes: nonce(24) || ciphertext+tag. */
export function encryptBytes(data: Uint8Array, keyHex: string): Uint8Array<ArrayBuffer> {
  return encrypt_raw(data, keyHex) as Uint8Array<ArrayBuffer>;
}

/** Decrypt lazynton wire bytes to the raw plaintext bytes.
 * Throws on tampered/short input or wrong key. */
export function decryptBytes(data: Uint8Array, keyHex: string): Uint8Array<ArrayBuffer> {
  if (data.length < MIN_WIRE_LEN) throw new Error("ciphertext too short");
  const plain = decrypt_raw(data, keyHex) as Uint8Array<ArrayBuffer>;
  // lazyxchacha reports an auth failure as an empty result rather than throwing.
  // A wire frame of exactly MIN_WIRE_LEN legitimately carries an empty plaintext.
  if (plain.length === 0 && data.length > MIN_WIRE_LEN) throw new Error("decrypt failed");
  return plain;
}

/** Encrypt UTF-8 plaintext to lazynton wire bytes: nonce(24) || ciphertext+tag. */
export function encryptToBinary(plaintext: string, keyHex: string): Uint8Array<ArrayBuffer> {
  return encryptBytes(utf8Encoder.encode(plaintext), keyHex);
}

/** Decrypt lazynton wire bytes to UTF-8 plaintext. Throws on tampered/short input or wrong key. */
export function decryptFromBinary(data: Uint8Array, keyHex: string): string {
  const plain = decryptBytes(data, keyHex);
  if (plain.length === 0) throw new Error("decrypt failed");
  return utf8Decoder.decode(plain);
}

// ---------------------------------------------------------------------------
// Session storage
// ---------------------------------------------------------------------------

/** Web Storage API subset, sync or async — localStorage plugs in directly,
 * and so do async stores (encrypted, React Native AsyncStorage, ...). */
export interface SessionStore {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export function memoryStore(): SessionStore {
  const m = new Map<string, string>();
  return {
    getItem: (k) => m.get(k) ?? null,
    setItem: (k, v) => void m.set(k, v),
    removeItem: (k) => void m.delete(k),
  };
}

/** AES-GCM key for secureStore, held non-extractable in IndexedDB — the raw
 * key bytes can never be read out of the browser. */
function idbAesKey(): Promise<CryptoKey> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("lazynton", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const get = db.transaction("keys").objectStore("keys").get("aes");
      get.onerror = () => reject(get.error);
      get.onsuccess = async () => {
        if (get.result) return resolve(get.result as CryptoKey);
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
          "encrypt",
          "decrypt",
        ]);
        const put = db.transaction("keys", "readwrite").objectStore("keys").put(key, "aes");
        put.onsuccess = () => resolve(key);
        put.onerror = () => reject(put.error);
      };
    };
  });
}

/** Wrap a store so values are encrypted at rest (AES-GCM, iv(12) || ct as hex).
 * Default key is non-extractable and lives in IndexedDB; the backing store
 * (localStorage by default) only ever sees ciphertext. */
export function secureStore(
  backing?: SessionStore,
  key: CryptoKey | Promise<CryptoKey> = idbAesKey(),
): SessionStore {
  const back = backing ?? globalThis.localStorage ?? memoryStore();
  const keyP = Promise.resolve(key);
  return {
    async getItem(k) {
      const raw = await back.getItem(k);
      if (!raw) return null;
      try {
        await ready();
        const data = from_hex(raw) as Uint8Array<ArrayBuffer>;
        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: data.subarray(0, 12) },
          await keyP,
          data.subarray(12),
        );
        return utf8Decoder.decode(plain);
      } catch {
        return null; // corrupted / different key → treat as absent
      }
    },
    async setItem(k, v) {
      await ready();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyP, utf8Encoder.encode(v)),
      );
      const blob = new Uint8Array(iv.length + ct.length);
      blob.set(iv);
      blob.set(ct, iv.length);
      await back.setItem(k, to_hex(blob));
    },
    removeItem: (k) => back.removeItem(k),
  };
}

function defaultStore(): SessionStore {
  try {
    if (globalThis.indexedDB && crypto.subtle && globalThis.localStorage) return secureStore();
    if (globalThis.localStorage) return globalThis.localStorage;
  } catch {} // some browsers throw on localStorage access (privacy mode)
  return memoryStore();
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export interface HandshakeResponse {
  sessionId: string;
  serverPublicKey: string;
  expiresIn: number;
}

/** Handshake wire format. "binary" is lazynton's native path — 32 raw key
 * bytes out, a 52-byte frame back, no JSON and no hex. "json" is the legacy
 * hex form kept for servers that predate it. "auto" uses binary and falls back
 * to JSON once if the server rejects it. */
export type HandshakeFormat = "binary" | "json" | "auto";

export interface LazyntonOptions {
  /** Handshake endpoint path. Default "/handshake". */
  handshakePath?: string;
  /** Handshake wire format. Default "auto". */
  handshakeFormat?: HandshakeFormat;
  /** Session persistence. Default: encrypted-at-rest localStorage in browsers
   * (secureStore), otherwise in-memory. */
  storage?: SessionStore;
  /** Storage key. Default "lazynton:<baseUrl>". */
  storageKey?: string;
}

interface StoredSession {
  sessionId: string;
  key: string;
  expiresAt: number;
}

export class LazyntonError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "LazyntonError";
  }
}

/**
 * Manages the E2EE session end to end: lazy X25519 handshake, persistence
 * (restored across reloads), expiry. HTTP-client-agnostic — pair it with
 * wrapFetch(), attachAxios(), or call encryptRequest()/decryptResponse()
 * from any middleware.
 */
export class E2eeSession {
  private key = "";
  private sessionId?: string;
  private handshakePath?: string;
  private format: HandshakeFormat;
  private store: SessionStore;
  private storeKey: string;
  private loaded = false;
  private pendingHandshake?: Promise<void>;

  constructor(
    readonly baseUrl: string,
    opts: LazyntonOptions = {},
  ) {
    this.handshakePath = opts.handshakePath ?? "/handshake";
    this.format = opts.handshakeFormat ?? "auto";
    this.store = opts.storage ?? defaultStore();
    this.storeKey = opts.storageKey ?? `lazynton:${baseUrl}`;
  }

  /** Pre-shared fallback key (hex 32 bytes) — no handshake, no session header. */
  static withSharedKey(baseUrl: string, keyHex: string): E2eeSession {
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) throw new Error("key must be 32 bytes hex (64 chars)");
    const session = new E2eeSession(baseUrl, { storage: memoryStore() });
    session.handshakePath = undefined;
    session.key = keyHex;
    session.loaded = true;
    return session;
  }

  /** False in pre-shared-key mode — a 401 then is not recoverable by re-handshake. */
  get usesHandshake(): boolean {
    return this.handshakePath !== undefined;
  }

  /** Force a fresh handshake now (otherwise it happens lazily on first use).
   * Concurrent callers share one in-flight handshake. */
  handshake(): Promise<void> {
    this.pendingHandshake ??= this.doHandshake().finally(() => (this.pendingHandshake = undefined));
    return this.pendingHandshake;
  }

  /** Drop the current session (e.g. after a 401); next use re-handshakes. */
  async invalidate(): Promise<void> {
    this.key = "";
    this.sessionId = undefined;
    this.loaded = true;
    await this.store.removeItem(this.storeKey);
  }

  /** Encrypted body + headers (content-type, x-session-id) for a request.
   * Handshakes first if there is no session yet. */
  async encryptRequest(
    plaintext: string,
  ): Promise<{ body: Uint8Array<ArrayBuffer>; headers: Record<string, string> }> {
    return this.encryptRequestBytes(utf8Encoder.encode(plaintext));
  }

  /** Byte-level counterpart of encryptRequest — for bodies that are already
   * binary, so nothing is converted to a string on the way out. */
  async encryptRequestBytes(
    data: Uint8Array,
  ): Promise<{ body: Uint8Array<ArrayBuffer>; headers: Record<string, string> }> {
    const key = await this.ensureKey();
    const headers: Record<string, string> = { "content-type": "application/octet-stream" };
    if (this.sessionId) headers["x-session-id"] = this.sessionId;
    return { body: encryptBytes(data, key), headers };
  }

  /** Decrypt a response body back to the plaintext (JSON) string. */
  async decryptResponse(data: ArrayBuffer | Uint8Array): Promise<string> {
    const plain = await this.decryptResponseBytes(data);
    if (plain.length === 0) throw new Error("decrypt failed");
    return utf8Decoder.decode(plain);
  }

  /** Byte-level counterpart of decryptResponse — hand the bytes straight to a
   * Response/Blob instead of materialising an intermediate string. */
  async decryptResponseBytes(data: ArrayBuffer | Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    const key = await this.ensureKey();
    return decryptBytes(data instanceof Uint8Array ? data : new Uint8Array(data), key);
  }

  private async ensureKey(): Promise<string> {
    // Every encrypt/decrypt path funnels through here, so this is the one place
    // the browser build's wasm has to be guaranteed live.
    await ready();
    if (!this.loaded) {
      this.loaded = true;
      try {
        const saved = JSON.parse((await this.store.getItem(this.storeKey)) ?? "") as StoredSession;
        // A malformed key would trap inside wasm rather than fail cleanly, so
        // check the format once here instead of on every encrypt.
        if (saved.expiresAt > Date.now() && KEY_HEX.test(saved.key)) {
          this.key = saved.key;
          this.sessionId = saved.sessionId;
        }
      } catch {} // nothing saved or corrupted → handshake below
    }
    if (!this.key) await this.handshake();
    return this.key;
  }

  private async doHandshake(): Promise<void> {
    await ready();
    const kp = new_keypair();
    const clientPublicKey = kp.pk;
    const clientSecretKey = kp.sk;
    kp.free(); // wasm-owned handle — release it now rather than waiting on the finalizer

    const url = this.baseUrl + this.handshakePath;
    const body =
      this.format === "json"
        ? await this.handshakeJson(url, clientPublicKey)
        : await this.handshakeBinary(url, clientPublicKey);

    this.key = shared_key(body.serverPublicKey, clientSecretKey);
    this.sessionId = body.sessionId;
    this.loaded = true;
    try {
      await this.store.setItem(
        this.storeKey,
        JSON.stringify({
          sessionId: this.sessionId,
          key: this.key,
          expiresAt: Date.now() + body.expiresIn * 1000,
        } satisfies StoredSession),
      );
    } catch {} // storage full/unavailable → session still works in memory
  }

  /** lazynton's native handshake: the public key goes out as 32 raw bytes and
   * comes back as a fixed 52-byte frame — no JSON, no hex on either side. */
  private async handshakeBinary(url: string, publicKeyHex: string): Promise<HandshakeResponse> {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: from_hex(publicKeyHex) as Uint8Array<ArrayBuffer>,
    });
    if (!res.ok) {
      if (this.format === "auto" && LEGACY_HANDSHAKE_STATUS.has(res.status)) {
        this.format = "json"; // probe the binary path once, not on every handshake
        return this.handshakeJson(url, publicKeyHex);
      }
      throw new LazyntonError(res.status, handshakeFailure(res.status));
    }
    const frame = new Uint8Array(await res.arrayBuffer());
    if (frame.length !== HANDSHAKE_RESPONSE_LEN) {
      throw new LazyntonError(
        res.status,
        `handshake failed: expected a ${HANDSHAKE_RESPONSE_LEN}-byte frame, got ${frame.length}`,
      );
    }
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    return {
      sessionId: to_hex(frame.subarray(0, SESSION_ID_LEN)), // hex for the X-Session-Id header
      serverPublicKey: to_hex(frame.subarray(SESSION_ID_LEN, SESSION_ID_LEN + PUBLIC_KEY_LEN)),
      expiresIn: view.getUint32(SESSION_ID_LEN + PUBLIC_KEY_LEN), // big-endian
    };
  }

  /** Legacy all-hex JSON handshake, for servers without the binary endpoint. */
  private async handshakeJson(url: string, publicKeyHex: string): Promise<HandshakeResponse> {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientPublicKey: publicKeyHex }),
    });
    if (!res.ok) throw new LazyntonError(res.status, handshakeFailure(res.status));
    return (await res.json()) as HandshakeResponse;
  }
}

function handshakeFailure(status: number): string {
  const detail = WIRE_ERRORS[status];
  return `handshake failed: HTTP ${status}${detail ? ` — ${detail}` : ""}`;
}

// ---------------------------------------------------------------------------
// HTTP client adapters
// ---------------------------------------------------------------------------

/**
 * fetch-compatible wrapper: pass a JSON string body as usual; it is encrypted
 * on the way out and the response is decrypted back into a JSON Response
 * (res.json() just works). 401 → one silent re-handshake + retry. Plugs into
 * anything that accepts a custom fetch (ky, SWR, openapi-fetch, ...).
 */
export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export function wrapFetch(session: E2eeSession, baseFetch: FetchLike = fetch): FetchLike {
  const send = async (input: RequestInfo | URL, init: RequestInit) => {
    const raw = init.body;
    // Binary bodies stay binary; only strings need encoding.
    const { body, headers } =
      raw instanceof Uint8Array
        ? await session.encryptRequestBytes(raw)
        : raw instanceof ArrayBuffer
          ? await session.encryptRequestBytes(new Uint8Array(raw))
          : await session.encryptRequest((raw as string) ?? "");
    const merged = new Headers(init.headers);
    for (const [k, v] of Object.entries(headers)) merged.set(k, v);
    return baseFetch(input, { ...init, headers: merged, body });
  };
  return async (input, init = {}) => {
    let res = await send(input, init);
    if (res.status === 401 && session.usesHandshake) {
      await session.invalidate();
      res = await send(input, init);
    }
    if (!res.headers.get("content-type")?.includes("application/octet-stream")) return res;
    // Bytes go straight into the Response — res.json() decodes them once, so the
    // plaintext is never materialised as a JS string here.
    const plain = await session.decryptResponseBytes(await res.arrayBuffer());
    return new Response(plain, {
      status: res.status,
      statusText: res.statusText,
      headers: { "content-type": "application/json" },
    });
  };
}

/** Structural subset of an axios instance — keeps axios out of our deps. */
interface AxiosLike {
  interceptors: {
    request: { use(onFulfilled: (config: any) => any): any };
    response: { use(onFulfilled: (res: any) => any, onRejected: (err: any) => any): any };
  };
  request(config: any): Promise<any>;
}

/**
 * Attach E2EE to an axios instance: request bodies are encrypted, responses
 * decrypted back to parsed JSON, 401 → one silent re-handshake + retry.
 *
 *   const api = axios.create({ baseURL });
 *   attachAxios(api, new E2eeSession(baseURL));
 */
export function attachAxios(axios: AxiosLike, session: E2eeSession): void {
  axios.interceptors.request.use(async (config) => {
    // Stash the plaintext so a 401 retry re-encrypts the original, not bytes.
    config.__e2eePlain ??=
      typeof config.data === "string" ? config.data : JSON.stringify(config.data ?? {});
    const { body, headers } = await session.encryptRequest(config.__e2eePlain);
    Object.assign(config.headers, headers);
    config.data = body;
    config.responseType = "arraybuffer";
    return config;
  });
  axios.interceptors.response.use(
    async (res) => {
      if (String(res.headers?.["content-type"]).includes("application/octet-stream")) {
        res.data = JSON.parse(await session.decryptResponse(res.data));
      }
      return res;
    },
    async (err) => {
      if (err.response?.status === 401 && session.usesHandshake && !err.config?.__e2eeRetried) {
        err.config.__e2eeRetried = true;
        await session.invalidate();
        return axios.request(err.config);
      }
      throw err;
    },
  );
}

// ---------------------------------------------------------------------------
// High-level client
// ---------------------------------------------------------------------------

/**
 * Batteries-included client over E2eeSession + wrapFetch:
 *
 *   const client = new LazyntonClient("https://api.example.com");
 *   const res = await client.post("/data", { msg: "hi" });
 */
export class LazyntonClient {
  readonly session: E2eeSession;
  private fetch: FetchLike;

  constructor(baseUrl: string, opts: LazyntonOptions = {}) {
    this.session = new E2eeSession(baseUrl, opts);
    this.fetch = wrapFetch(this.session);
  }

  /** Pre-shared fallback key (hex 32 bytes) — no handshake, no session header. */
  static withSharedKey(baseUrl: string, keyHex: string): LazyntonClient {
    const client = new LazyntonClient(baseUrl);
    (client as { session: E2eeSession }).session = E2eeSession.withSharedKey(baseUrl, keyHex);
    client.fetch = wrapFetch(client.session);
    return client;
  }

  /** POST JSON to an encrypted endpoint; decrypts and parses the JSON response. */
  async post<T = unknown>(path: string, body: unknown): Promise<T> {
    const res = await this.fetch(this.session.baseUrl + path, {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      // lazynton answers wire errors with a bare status and an empty body.
      const body = await res.text().catch(() => "");
      throw new LazyntonError(res.status, body || WIRE_ERRORS[res.status] || res.statusText);
    }
    return res.json() as Promise<T>;
  }
}
