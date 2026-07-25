# lazynton-js

TypeScript E2EE client for [lazynton](https://github.com/prongbang/lazynton-rs)
(axum end-to-end encryption middleware), built on
[lazyxchacha](https://www.npmjs.com/package/lazyxchacha) (XChaCha20-Poly1305 + X25519).

Wire format: `application/octet-stream` body = raw `nonce(24) || ciphertext+tag`.

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
```

## Options

```ts
new LazyntonClient(baseUrl, {          // same options for E2eeSession
  handshakePath: "/handshake",         // default
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
import { encryptToBinary, decryptFromBinary } from "lazynton-js";

const wire = encryptToBinary('{"msg":"hi"}', keyHex); // Uint8Array: nonce || ct
const plain = decryptFromBinary(wire, keyHex);        // throws on tamper/wrong key
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

## Test

```bash
bun test
```

Includes a cross-language fixture (Rust `lazyxchacha` crate ↔ this client, both
directions) and end-to-end tests for the fetch wrapper and a real axios instance
against a mock lazynton server.

## License

MIT
