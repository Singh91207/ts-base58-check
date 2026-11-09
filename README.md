# ts-base58-check

Encode and decode Base58Check strings with a pluggable one-byte checksum and a choice of Bitcoin or Ripple alphabet.

```js
import { encode, decode, createCodec } from 'ts-base58-check';

// Simple API: Bitcoin alphabet, checksum byte 0x00.
const text = encode(new Uint8Array([1, 2, 3]));
const payload = decode(text); // Uint8Array [1, 2, 3]

// Custom checksum and alphabet.
const ripple = createCodec({ checksum: 0x2a, alphabet: 'ripple' });
const encoded = ripple.encode(new Uint8Array([0xde, 0xad]));
const decoded = ripple.decode(encoded); // Uint8Array [0xde, 0xad]
```

## Why this exists

Base58Check is usually tied to a fixed four-byte double-SHA256 checksum and the Bitcoin alphabet. Some systems, notably Ripple, use a different alphabet, and some protocols want a checksum byte they choose themselves. This library exposes the checksum as a single byte and the alphabet as a named option, so callers can match those systems without pulling in a hashing dependency.

The trade-off is integrity strength: a one-byte checksum catches 255 out of 256 single-byte errors, not the near-certainty of a four-byte hash. If you need stronger detection, compute a hash over the payload yourself and pass the whole thing as the payload.

## Exports

- `encode(payload, checksum = 0)` — payload is a `Uint8Array`; returns a Base58 string using the Bitcoin alphabet.
- `decode(str, checksum = 0)` — returns the payload `Uint8Array`; throws if the checksum does not match.
- `createCodec({ checksum = 0, alphabet = 'bitcoin' })` — returns `{ encode, decode }` bound to those settings. `alphabet` must be `'bitcoin'` or `'ripple'`.

## Edge cases

Leading zero bytes are significant and are preserved: each one becomes a leading `1` (Bitcoin) or `r` (Ripple) in the encoded string. An empty decoded result is rejected because it cannot carry a checksum byte. Invalid characters and checksum mismatches throw `Error`; type and range problems throw `TypeError` or `RangeError`.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

