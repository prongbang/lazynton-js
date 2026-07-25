// TypeScript client for lazynton (axum E2EE middleware), built on the
// lazyxchacha npm package (XChaCha20-Poly1305 + X25519, hex API).
// Wire format: application/octet-stream body = raw nonce(24) || ciphertext+tag
// — lazyxchacha's hex output decoded to bytes.

import { decrypt, encrypt, generateKeyPair, sharedKey } from "lazyxchacha";

const MIN_WIRE_LEN = 24 + 16; // nonce + poly1305 tag

function hexToBytes(hexStr: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Encrypt UTF-8 plaintext to lazynton wire bytes: nonce(24) || ciphertext+tag. */
export function encryptToBinary(plaintext: string, keyHex: string): Uint8Array<ArrayBuffer> {
  return hexToBytes(encrypt(plaintext, keyHex));
}

/** Decrypt lazynton wire bytes to UTF-8 plaintext. Throws on tampered/short input or wrong key. */
export function decryptFromBinary(data: Uint8Array, keyHex: string): string {
  if (data.length < MIN_WIRE_LEN) throw new Error("ciphertext too short");
  const plaintext = decrypt(bytesToHex(data), keyHex);
  if (!plaintext) throw new Error("decrypt failed");
  return plaintext;
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
        const data = hexToBytes(raw);
        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: data.subarray(0, 12) },
          await keyP,
          data.subarray(12),
        );
        return new TextDecoder().decode(plain);
      } catch {
        return null; // corrupted / different key → treat as absent
      }
    },
    async setItem(k, v) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyP, new TextEncoder().encode(v)),
      );
      const blob = new Uint8Array(iv.length + ct.length);
      blob.set(iv);
      blob.set(ct, iv.length);
      await back.setItem(k, bytesToHex(blob));
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

export interface LazyntonOptions {
  /** Handshake endpoint path. Default "/handshake". */
  handshakePath?: string;
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
  private store: SessionStore;
  private storeKey: string;
  private loaded = false;
  private pendingHandshake?: Promise<void>;

  constructor(
    readonly baseUrl: string,
    opts: LazyntonOptions = {},
  ) {
    this.handshakePath = opts.handshakePath ?? "/handshake";
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
    const key = await this.ensureKey();
    const headers: Record<string, string> = { "content-type": "application/octet-stream" };
    if (this.sessionId) headers["x-session-id"] = this.sessionId;
    return { body: encryptToBinary(plaintext, key), headers };
  }

  /** Decrypt a response body back to the plaintext (JSON) string. */
  async decryptResponse(data: ArrayBuffer | Uint8Array): Promise<string> {
    const key = await this.ensureKey();
    return decryptFromBinary(data instanceof Uint8Array ? data : new Uint8Array(data), key);
  }

  private async ensureKey(): Promise<string> {
    if (!this.loaded) {
      this.loaded = true;
      try {
        const saved = JSON.parse((await this.store.getItem(this.storeKey)) ?? "") as StoredSession;
        if (saved.expiresAt > Date.now()) {
          this.key = saved.key;
          this.sessionId = saved.sessionId;
        }
      } catch {} // nothing saved or corrupted → handshake below
    }
    if (!this.key) await this.handshake();
    return this.key;
  }

  private async doHandshake(): Promise<void> {
    const kp = generateKeyPair();
    const res = await fetch(this.baseUrl + this.handshakePath, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientPublicKey: kp.pk }),
    });
    if (!res.ok) throw new LazyntonError(res.status, `handshake failed: HTTP ${res.status}`);
    const body = (await res.json()) as HandshakeResponse;
    this.key = sharedKey(kp.sk, body.serverPublicKey);
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
    const { body, headers } = await session.encryptRequest((init.body as string) ?? "");
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
    const plain = await session.decryptResponse(await res.arrayBuffer());
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
      throw new LazyntonError(res.status, (await res.text().catch(() => "")) || res.statusText);
    }
    return res.json() as Promise<T>;
  }
}
