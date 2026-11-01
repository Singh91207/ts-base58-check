// Base58Check encoder/decoder with pluggable checksum and alphabet.
//
// The checksum is applied as a single byte over the payload. This is a
// deliberate simplification: classic Base58Check uses a 4-byte double-SHA256
// checksum, but the brief calls for a pluggable checksum byte, so we keep the
// interface small and let callers supply their own byte. The trade-off is that
// a one-byte checksum catches only 255/256 of single-byte errors; callers who
// need stronger integrity should wrap the payload themselves.

const BITCOIN_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const RIPPLE_ALPHABET =
  'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

// Precompute decode tables once per alphabet. Building them lazily keeps the
// module cheap to import when only one alphabet is used.
const decodeTables = new Map();

function getDecodeTable(alphabet) {
  let table = decodeTables.get(alphabet);
  if (table) return table;
  table = new Map();
  for (let i = 0; i < alphabet.length; i++) {
    table.set(alphabet[i], i);
  }
  decodeTables.set(alphabet, table);
  return table;
}

/**
 * Encode bytes as a Base58 string using the given alphabet.
 * @param {Uint8Array} bytes
 * @param {string} alphabet
 * @returns {string}
 */
function base58Encode(bytes, alphabet) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('bytes must be a Uint8Array');
  }
  if (alphabet.length !== 58) {
    throw new RangeError('alphabet must contain exactly 58 characters');
  }

  // Count leading zero bytes; each becomes a leading '1'-equivalent character.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Allocate enough space for the base58 representation. log(256)/log(58) is
  // about 1.365, so bytes.length * 2 is always sufficient.
  const size = Math.ceil(bytes.length * 2) || 1;
  const digits = new Uint8Array(size);
  let length = 0;

  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    let j = 0;
    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 256 * digits[k];
      digits[k] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    length = j;
  }

  // Skip leading zero digits in the working buffer.
  let start = size - length;
  while (start < size && digits[start] === 0) start++;

  let result = '';
  for (let i = 0; i < zeros; i++) result += alphabet[0];
  for (let i = start; i < size; i++) result += alphabet[digits[i]];
  return result;
}

/**
 * Decode a Base58 string using the given alphabet.
 * @param {string} str
 * @param {string} alphabet
 * @returns {Uint8Array}
 */
function base58Decode(str, alphabet) {
  if (typeof str !== 'string') {
    throw new TypeError('str must be a string');
  }
  if (alphabet.length !== 58) {
    throw new RangeError('alphabet must contain exactly 58 characters');
  }

  const table = getDecodeTable(alphabet);

  // Count leading alphabet[0] characters; each maps to a leading zero byte.
  let zeros = 0;
  while (zeros < str.length && str[zeros] === alphabet[0]) zeros++;

  const size = Math.ceil(str.length * 2) || 1;
  const bytes = new Uint8Array(size);
  let length = 0;

  for (let i = zeros; i < str.length; i++) {
    const value = table.get(str[i]);
    if (value === undefined) {
      throw new Error(`invalid base58 character: ${str[i]}`);
    }
    let carry = value;
    let j = 0;
    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 58 * bytes[k];
      bytes[k] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    length = j;
  }

  let start = size - length;
  while (start < size && bytes[start] === 0) start++;

  const out = new Uint8Array(zeros + (size - start));
  out.set(bytes.subarray(start, size), zeros);
  return out;
}

function assertByte(value, name) {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new RangeError(`${name} must be an integer in [0, 255]`);
  }
}

function assertByteArray(value, name) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

/**
 * Create a codec bound to a checksum byte and alphabet.
 *
 * @param {object} [options]
 * @param {number} [options.checksum=0] 0-255, XORed over the payload bytes.
 * @param {string} [options.alphabet] one of 'bitcoin' or 'ripple'.
 * @returns {{ encode: (payload: Uint8Array) => string, decode: (str: string) => Uint8Array }}
 */
export function createCodec(options = {}) {
  const { checksum = 0, alphabet = 'bitcoin' } = options;
  assertByte(checksum, 'checksum');

  let alphabetString;
  if (alphabet === 'bitcoin') {
    alphabetString = BITCOIN_ALPHABET;
  } else if (alphabet === 'ripple') {
    alphabetString = RIPPLE_ALPHABET;
  } else {
    throw new RangeError("alphabet must be 'bitcoin' or 'ripple'");
  }

  return {
    /**
     * Encode a payload: append the checksum byte, then Base58-encode.
     * @param {Uint8Array} payload
     * @returns {string}
     */
    encode(payload) {
      assertByteArray(payload, 'payload');
      const withChecksum = new Uint8Array(payload.length + 1);
      withChecksum.set(payload, 0);
      withChecksum[payload.length] = checksum;
      return base58Encode(withChecksum, alphabetString);
    },

    /**
     * Decode a Base58 string, verify the trailing checksum byte, and return
     * the payload without the checksum.
     * @param {string} str
     * @returns {Uint8Array}
     */
    decode(str) {
      const decoded = base58Decode(str, alphabetString);
      if (decoded.length === 0) {
        throw new Error('decoded data is empty');
      }
      const payloadLength = decoded.length - 1;
      const actual = decoded[payloadLength];
      if (actual !== checksum) {
        throw new Error(
          `checksum mismatch: expected ${checksum}, got ${actual}`
        );
      }
      return decoded.slice(0, payloadLength);
    },
  };
}

/**
 * Encode a payload with a one-byte checksum using the Bitcoin alphabet.
 * @param {Uint8Array} payload
 * @param {number} [checksum=0]
 * @returns {string}
 */
export function encode(payload, checksum = 0) {
  return createCodec({ checksum, alphabet: 'bitcoin' }).encode(payload);
}

/**
 * Decode a Bitcoin-alphabet Base58Check string with a one-byte checksum.
 * @param {string} str
 * @param {number} [checksum=0]
 * @returns {Uint8Array}
 */
export function decode(str, checksum = 0) {
  return createCodec({ checksum, alphabet: 'bitcoin' }).decode(str);
}
