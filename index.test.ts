import { expect, test } from "bun:test";
import axios from "axios";
import { generateKeyPair, sharedKey } from "lazyxchacha";
import {
  attachAxios,
  decryptFromBinary,
  E2eeSession,
  encryptToBinary,
  LazyntonClient,
  secureStore,
  wrapFetch,
  type SessionStore,
} from "./index.ts";

const KEY = "edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e";
// Produced by the Rust lazyxchacha 0.1.1 crate (same key, plaintext {"msg":"cross-language"}).
const RUST_FIXTURE_HEX =
  "2f97429e5b16e79e1b45a757d2c3ac6962a78128db2edc9c6b593db6c2e03e5d04033915865c5b1b28ed79f965b02500b7a1eda88b74a587679f1112a3e0ce9d";

function fromHex(hexStr: string): Uint8Array {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function mapStore(): SessionStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

// Mock lazynton server: /handshake + encrypted echo, counts handshakes.
function mockServer() {
  const sessions = new Map<string, string>();
  let handshakes = 0;
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/handshake") {
        handshakes++;
        const { clientPublicKey } = (await req.json()) as { clientPublicKey: string };
        const kp = generateKeyPair();
        const sid = crypto.randomUUID();
        sessions.set(sid, sharedKey(kp.sk, clientPublicKey));
        return Response.json({ sessionId: sid, serverPublicKey: kp.pk, expiresIn: 3600 });
      }
      const key = sessions.get(req.headers.get("x-session-id") ?? "");
      if (!key) return new Response("unauthorized", { status: 401 });
      const body = decryptFromBinary(new Uint8Array(await req.arrayBuffer()), key);
      return new Response(encryptToBinary(JSON.stringify({ echo: JSON.parse(body) }), key), {
        headers: { "content-type": "application/octet-stream" },
      });
    },
  });
  return { server, sessions, handshakes: () => handshakes };
}

test("binary roundtrip", () => {
  const plaintext = '{"bundleId":"com.example.app"}';
  const wire = encryptToBinary(plaintext, KEY);
  expect(wire.length).toBe(24 + plaintext.length + 16);
  expect(decryptFromBinary(wire, KEY)).toBe(plaintext);
});

test("decrypts ciphertext produced by the Rust implementation", () => {
  expect(decryptFromBinary(fromHex(RUST_FIXTURE_HEX), KEY)).toBe('{"msg":"cross-language"}');
});

test("rejects short, tampered, and wrong-key input", () => {
  const wire = encryptToBinary("{}", KEY);
  expect(() => decryptFromBinary(wire.subarray(0, 10), KEY)).toThrow();
  const tampered = Uint8Array.from(wire);
  tampered[tampered.length - 1]! ^= 1;
  expect(() => decryptFromBinary(tampered, KEY)).toThrow();
  expect(() => decryptFromBinary(wire, "00".repeat(32))).toThrow();
});

test("both sides of an X25519 exchange derive the same key", () => {
  const client = generateKeyPair();
  const server = generateKeyPair();
  expect(sharedKey(client.sk, server.pk)).toBe(sharedKey(server.sk, client.pk));
});

test("withSharedKey validates key format", () => {
  expect(() => LazyntonClient.withSharedKey("http://x", "not-hex")).toThrow();
});

test("auto-handshake on first post, then reuses the session", async () => {
  const { server, handshakes } = mockServer();
  using srv = server;
  const client = new LazyntonClient(srv.url.origin);
  const res = await client.post<{ echo: { msg: string } }>("/echo", { msg: "hi" });
  expect(res.echo.msg).toBe("hi");
  await client.post("/echo", { msg: "again" });
  expect(handshakes()).toBe(1);
});

test("session persists via storage across client instances", async () => {
  const { server, handshakes } = mockServer();
  using srv = server;
  const storage = mapStore();

  const first = new LazyntonClient(srv.url.origin, { storage });
  await first.post("/echo", { n: 1 });
  expect(handshakes()).toBe(1);

  // "Page reload": new instance, same storage → restored session, no handshake.
  const second = new LazyntonClient(srv.url.origin, { storage });
  const res = await second.post<{ echo: { n: number } }>("/echo", { n: 2 });
  expect(res.echo.n).toBe(2);
  expect(handshakes()).toBe(1);
});

test("expired stored session and server-side 401 both trigger re-handshake", async () => {
  const { server, sessions, handshakes } = mockServer();
  using srv = server;
  const storage = mapStore();

  const client = new LazyntonClient(srv.url.origin, { storage });
  await client.post("/echo", { n: 1 });

  // Server lost the session → 401 → silent re-handshake + retry.
  sessions.clear();
  const res = await client.post<{ echo: { n: number } }>("/echo", { n: 2 });
  expect(res.echo.n).toBe(2);
  expect(handshakes()).toBe(2);

  // Stored session already expired by its own clock → fresh handshake on construct.
  const key = [...storage.map.keys()][0]!;
  const stale = { ...JSON.parse(storage.map.get(key)!), expiresAt: Date.now() - 1 };
  storage.map.set(key, JSON.stringify(stale));
  const reloaded = new LazyntonClient(srv.url.origin, { storage });
  await reloaded.post("/echo", { n: 3 });
  expect(handshakes()).toBe(3);
});

test("concurrent first posts share one handshake", async () => {
  const { server, handshakes } = mockServer();
  using srv = server;
  const client = new LazyntonClient(srv.url.origin);
  await Promise.all([client.post("/echo", { a: 1 }), client.post("/echo", { a: 2 })]);
  expect(handshakes()).toBe(1);
});

test("secureStore encrypts at rest and survives roundtrip", async () => {
  const backing = mapStore();
  const aes = crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const store = secureStore(backing, aes);

  await store.setItem("s", '{"sessionId":"sid","key":"k"}');
  expect(await store.getItem("s")).toBe('{"sessionId":"sid","key":"k"}');
  // Backing store only ever sees ciphertext.
  expect(backing.map.get("s")).not.toContain("sid");
  // A different key (fresh browser profile) can't read it → treated as absent.
  const otherKey = crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  expect(await secureStore(backing, otherKey).getItem("s")).toBeNull();
  await store.removeItem("s");
  expect(await store.getItem("s")).toBeNull();
});

test("wrapFetch: drop-in fetch with transparent E2EE and 401 retry", async () => {
  const { server, sessions, handshakes } = mockServer();
  using srv = server;
  const efetch = wrapFetch(new E2eeSession(srv.url.origin));

  const res = await efetch(`${srv.url.origin}/echo`, {
    method: "POST",
    body: JSON.stringify({ via: "fetch" }),
  });
  expect(res.ok).toBe(true);
  expect((await res.json()).echo.via).toBe("fetch");

  sessions.clear(); // server lost the session → silent re-handshake + retry
  const res2 = await efetch(`${srv.url.origin}/echo`, {
    method: "POST",
    body: JSON.stringify({ via: "retry" }),
  });
  expect((await res2.json()).echo.via).toBe("retry");
  expect(handshakes()).toBe(2);
});

test("attachAxios: transparent E2EE on a real axios instance with 401 retry", async () => {
  const { server, sessions, handshakes } = mockServer();
  using srv = server;
  const api = axios.create({ baseURL: srv.url.origin });
  attachAxios(api, new E2eeSession(srv.url.origin));

  const res = await api.post("/echo", { via: "axios" });
  expect(res.data.echo.via).toBe("axios");

  sessions.clear();
  const res2 = await api.post("/echo", { via: "axios-retry" });
  expect(res2.data.echo.via).toBe("axios-retry");
  expect(handshakes()).toBe(2);
});
