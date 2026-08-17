# lazynton-js

TypeScript E2EE client for [lazynton](https://github.com/prongbang/lazynton-rs)
(axum end-to-end encryption middleware), built on
[lazyxchacha](https://www.npmjs.com/package/lazyxchacha) 1.0.5 — the WebAssembly
build of the Rust implementation (XChaCha20-Poly1305 + X25519). Speaks
[lazynton-rs](https://github.com/prongbang/lazynton-rs) 0.3's binary wire end to end.

Wire format: `application/octet-stream` body = raw `nonce(24) || ciphertext+tag`,
read and written through lazyxchacha's raw byte API so payloads never round-trip
through a hex string — 7–20× faster than the hex path, the gap widening with
payload size.

> **Runtime:** lazyxchacha 1.0.5 ships a Node-target wasm build (`require('fs')`,
> CommonJS only). It runs under Node and Bun; bundling it for a browser needs a
> web-target wasm build of lazyxchacha, which 1.0.5 does not publish.

## Install

```bash
npm install lazynton-js
# or
bun add lazynton-js
```

## Quick start

```ts
import { LazyntonClient } from "lazynton-js";

const client = new LazyntonClient("http://localhost:3000");
const res = await client.post<{ ok: boolean }>("/data", { bundleId: "com.example.app" });
```

The session lifecycle is fully managed — no handshake code needed:

- First request performs the X25519 handshake automatically.
- The session (id + shared key) is persisted **encrypted at rest**: AES-GCM under a
  non-extractable `CryptoKey` kept in IndexedDB, ciphertext in localStorage.
  The key bytes can never be read out of the browser; a copied localStorage is useless.
- Restored on reload — no re-handshake per page load; expired sessions are dropped.
- 401 (expired/unknown session) → one silent re-handshake + retry.
- Concurrent first calls share a single in-flight handshake.

## Use with fetch, axios, or anything else

The session core (`E2eeSession`) is HTTP-client-agnostic:

```ts
import { E2eeSession, wrapFetch, attachAxios } from "lazynton-js";

const session = new E2eeSession("http://localhost:3000");

// fetch (also ky, SWR, openapi-fetch — anything accepting a custom fetch)
const efetch = wrapFetch(session);
const res = await efetch("http://localhost:3000/data", {
  method: "POST",
  body: JSON.stringify({ msg: "hi" }),
});
await res.json(); // decrypted transparently

// axios
const api = axios.create({ baseURL: "http://localhost:3000" });
attachAxios(api, session);
await api.post("/data", { msg: "hi" }); // res.data is decrypted JSON

// any other middleware — two calls do everything:
const { body, headers } = await session.encryptRequest('{"msg":"hi"}');
const plain = await session.decryptResponse(responseBytes);

// already-binary payloads: skip the string hop entirely
const { body } = await session.encryptRequestBytes(new Uint8Array(buf));
const bytes = await session.decryptResponseBytes(responseBytes);
```

## Options

```ts
new LazyntonClient(baseUrl, {          // same options for E2eeSession
  handshakePath: "/handshake",         // default
  handshakeFormat: "auto",             // default — "binary" | "json" | "auto"
  storage: sessionStorage,             // any sync/async get/set/removeItem
  storageKey: "lazynton:<baseUrl>",    // default
});

// storage helpers
secureStore(backing?)                  // encrypted-at-rest wrapper (the default in browsers)
memoryStore()                          // no persistence (the default outside browsers)

// Pre-shared fallback key (hex 32 bytes) — skips handshake entirely
LazyntonClient.withSharedKey(baseUrl, process.env.E2EE_SHARED_KEY!);
```

Low-level helpers mirroring the Rust side:

```ts
import { encryptToBinary, decryptFromBinary, encryptBytes, decryptBytes } from "lazynton-js";

const wire = encryptToBinary('{"msg":"hi"}', keyHex); // Uint8Array: nonce || ct
const plain = decryptFromBinary(wire, keyHex);        // throws on tamper/wrong key

// byte-in/byte-out variants for binary payloads — no UTF-8 conversion at all
const wireBytes = encryptBytes(new Uint8Array([1, 2, 3]), keyHex);
const plainBytes = decryptBytes(wireBytes, keyHex);
```

## Server side

See [lazynton](https://github.com/prongbang/lazynton-rs) for the axum middleware:

```rust
let e2ee = E2ee::new(std::env::var("E2EE_SHARED_KEY").ok());
let app = Router::new()
    .route("/data", post(handler).layer(
        axum::middleware::from_fn_with_state(e2ee.clone(), lazynton::middleware),
    ))
    .merge(e2ee.handshake_router("/handshake"));
```

### Handshake

lazynton 0.3 answers `/handshake` in two formats, picked by the request's
`Content-Type`. This client uses the binary one by default:

| | request | response |
|---|---|---|
| **binary** (default) | `application/octet-stream`, 32 raw key bytes | 52 bytes: `sessionId(16) \|\| serverPublicKey(32) \|\| expiresIn(u32 BE)` |
| **json** (legacy) | `{"clientPublicKey": "<hex>"}` | `{"sessionId", "serverPublicKey", "expiresIn"}`, all hex |

`handshakeFormat: "auto"` (the default) sends binary and falls back to JSON once
if the server rejects it, so servers older than 0.3 keep working; the fallback is
remembered for the life of the session. Pin `"binary"` or `"json"` to skip the probe.

### Server-side limits worth knowing

- `max_body_bytes` defaults to **64 KB** — a larger request comes back as `413`.
  Raise it with `E2ee::with_config(fallback_key, ttl, max_sessions, max_body_bytes)`.
- Non-2xx responses pass through **unencrypted**, so error bodies read normally.
- `LazyntonError.message` spells out lazynton's documented wire errors
  (400 key mismatch, 401 unknown/expired session, 413 too large, 415 wrong
  content type, 503 session table full), which axum returns with an empty body.

## Test

```bash
bun test
```

Includes a cross-language fixture (Rust `lazyxchacha` crate ↔ this client, both
directions) and end-to-end tests for the fetch wrapper and a real axios instance
against a mock lazynton server that speaks both handshake formats.

Verified against a real `lazynton` 0.3.0 axum server: binary and JSON handshakes,
session reuse, pre-shared fallback key, 401 → re-handshake + retry, 413 on an
oversized body, and 1 KB–512 KB payloads (256 KB echo round-trips in ~4 ms).

## License

MIT
