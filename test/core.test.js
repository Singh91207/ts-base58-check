import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encode, decode, createCodec } from '../src/index.js';

// Helper: convert an array of byte values to a Uint8Array.
function bytes(...values) {
  return Uint8Array.from(values);
}

// Helper: convert a Uint8Array to a plain array for comparison.
function toArray(u8) {
  return Array.from(u8);
}

test('round-trips a simple payload with the default checksum', () => {
  const payload = bytes(1, 2, 3);
  const encoded = encode(payload);
  const decoded = decode(encoded);
  assert.deepEqual(toArray(decoded), [1, 2, 3]);
});

test('round-trips a payload with a non-zero checksum', () => {
  const payload = bytes(10, 20, 30);
  const encoded = encode(payload, 0xff);
  const decoded = decode(encoded, 0xff);
  assert.deepEqual(toArray(decoded), [10, 20, 30]);
});

test('preserves leading zero bytes', () => {
  const payload = bytes(0, 0, 7);
  const encoded = encode(payload);
  assert.equal(encoded[0], '1');
  assert.equal(encoded[1], '1');
  const decoded = decode(encoded);
  assert.deepEqual(toArray(decoded), [0, 0, 7]);
});

test('handles an all-zero payload', () => {
  const payload = bytes(0, 0, 0);
  const encoded = encode(payload);
  const decoded = decode(encoded);
  assert.deepEqual(toArray(decoded), [0, 0, 0]);
});

test('rejects a corrupted checksum', () => {
  const encoded = encode(bytes(5, 6, 7), 1);
  assert.throws(() => decode(encoded, 2), /checksum mismatch/);
});

test('rejects invalid base58 characters', () => {
  // '0' is not in the Bitcoin alphabet.
  assert.throws(() => decode('0'), /invalid base58 character/);
});

test('rejects an empty decoded result', () => {
  // An empty string decodes to zero bytes, which cannot carry a checksum.
  assert.throws(() => decode(''), /decoded data is empty/);
});

test('rejects a non-Uint8Array payload', () => {
  assert.throws(() => encode([1, 2, 3]), TypeError);
});

test('rejects an out-of-range checksum', () => {
  assert.throws(() => createCodec({ checksum: 256 }), RangeError);
  assert.throws(() => createCodec({ checksum: -1 }), RangeError);
  assert.throws(() => createCodec({ checksum: 1.5 }), RangeError);
});

test('rejects an unknown alphabet name', () => {
  assert.throws(() => createCodec({ alphabet: 'base58' }), RangeError);
});

test('round-trips with the Ripple alphabet', () => {
  const codec = createCodec({ checksum: 0x2a, alphabet: 'ripple' });
  const payload = bytes(0xde, 0xad, 0xbe, 0xef);
  const encoded = codec.encode(payload);
  const decoded = codec.decode(encoded);
  assert.deepEqual(toArray(decoded), [0xde, 0xad, 0xbe, 0xef]);
});

test('Ripple and Bitcoin encodings differ for the same payload', () => {
  const payload = bytes(0xde, 0xad, 0xbe, 0xef);
  const bitcoin = createCodec({ checksum: 0x2a, alphabet: 'bitcoin' }).encode(payload);
  const ripple = createCodec({ checksum: 0x2a, alphabet: 'ripple' }).encode(payload);
  assert.notEqual(bitcoin, ripple);
});

test('decodes a known Bitcoin-alphabet vector', () => {
  // Manually computed: payload [0x00] with checksum 0x00 gives bytes
  // [0x00, 0x00], which is "11" in the Bitcoin alphabet.
  const decoded = decode('11');
  assert.deepEqual(toArray(decoded), [0x00]);
});

test('encodes a known Bitcoin-alphabet vector', () => {
  assert.equal(encode(bytes(0x00), 0x00), '11');
});
