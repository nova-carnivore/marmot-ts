/**
 * Marmot Protocol Cryptographic Utilities
 *
 * HKDF, ChaCha20-Poly1305, NIP-44 conversation key derivation,
 * and ephemeral keypair generation.
 */

import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { concatBytes, randomBytes } from './utils.js';

// ─── Hashing ────────────────────────────────────────────────────────────────

/**
 * Compute SHA-256 hash of data.
 */
export function sha256Hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Compute SHA-256 hash and return as hex string.
 */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

// ─── HKDF ───────────────────────────────────────────────────────────────────

/**
 * HKDF-Extract: Extract a fixed-length pseudorandom key from input keying material.
 */
export function hkdfExtract(ikm: Uint8Array, salt?: Uint8Array): Uint8Array {
  const result = hkdf(sha256, ikm, salt, undefined, 32);
  return new Uint8Array(result);
}

/**
 * HKDF-Expand: Expand a pseudorandom key using info to the desired length.
 */
export function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array | string,
  length: number = 32
): Uint8Array {
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  // Use hmac-based HKDF expand
  const hashLen = 32; // SHA-256
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = concatBytes(prev, infoBytes, new Uint8Array([i]));
    prev = new Uint8Array(hmac(sha256, prk, input));
    okm.set(prev, (i - 1) * hashLen);
  }

  return okm.slice(0, length);
}

// ─── secp256k1 Key Operations ───────────────────────────────────────────────

/**
 * Generate a new random secp256k1 keypair.
 * Returns { privateKey, publicKey } where publicKey is the x-only (32-byte) pubkey.
 */
export function generateKeypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
  privateKeyHex: string;
} {
  const privateKey = randomBytes(32);
  // Ensure the private key is valid for secp256k1
  const publicKeyFull = secp256k1.getPublicKey(privateKey, true);
  // x-only pubkey (drop the prefix byte)
  const publicKey = publicKeyFull.slice(1);
  return {
    privateKey,
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
    privateKeyHex: bytesToHex(privateKey),
  };
}

/**
 * Generate an ephemeral keypair (fresh, for a single use).
 * Critical: MUST be called fresh for every kind: 445 event.
 */
export function generateEphemeralKeypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
  privateKeyHex: string;
} {
  return generateKeypair();
}

/**
 * Derive a keypair from a private key (secret).
 */
export function keypairFromSecret(secret: Uint8Array): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  const publicKeyFull = secp256k1.getPublicKey(secret, true);
  const publicKey = publicKeyFull.slice(1);
  return {
    privateKey: secret,
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
  };
}

/**
 * Derive a keypair from a hex-encoded private key.
 */
export function keypairFromSecretHex(secretHex: string): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  return keypairFromSecret(hexToBytes(secretHex));
}

/**
 * Get the x-only public key (32 bytes) from a private key.
 */
export function getPublicKey(privateKey: Uint8Array): Uint8Array {
  const full = secp256k1.getPublicKey(privateKey, true);
  return full.slice(1);
}

/**
 * Get the x-only public key as hex from a hex private key.
 */
export function getPublicKeyHex(privateKeyHex: string): string {
  return bytesToHex(getPublicKey(hexToBytes(privateKeyHex)));
}

// ─── NIP-44 Key Derivation ──────────────────────────────────────────────────

/**
 * Compute a NIP-44 conversation key from sender private key and receiver public key.
 * Uses secp256k1 ECDH shared secret with HKDF.
 */
export function computeConversationKey(
  senderPrivateKey: Uint8Array,
  receiverPubkeyHex: string
): Uint8Array {
  // secp256k1 ECDH: shared point
  const receiverPoint = secp256k1.ProjectivePoint.fromHex('02' + receiverPubkeyHex);
  const sharedPoint = receiverPoint.multiply(BigInt('0x' + bytesToHex(senderPrivateKey)));
  const sharedX = sharedPoint.toAffine().x;
  // Convert field element to 32 bytes
  const sharedHex = sharedX.toString(16).padStart(64, '0');
  const sharedSecret = hexToBytes(sharedHex);

  // HKDF extract with "nip44-v2" salt
  const salt = new TextEncoder().encode('nip44-v2');
  return hkdf(sha256, sharedSecret, salt, undefined, 32);
}

/**
 * Derive a conversation key from the exporter secret (for MIP-03 group encryption).
 * The exporter_secret is used as both sender and receiver key.
 */
export function deriveGroupConversationKey(exporterSecret: Uint8Array): Uint8Array {
  // Use exporter_secret as private key, derive public key, then compute conversation key
  const pubkeyHex = getPublicKeyHex(bytesToHex(exporterSecret));
  return computeConversationKey(exporterSecret, pubkeyHex);
}

// ─── ChaCha20-Poly1305 (for MIP-01 group images and MIP-04 media) ──────────

/**
 * ChaCha20 quarter-round.
 */
function quarterRound(
  state: Uint32Array,
  a: number,
  b: number,
  c: number,
  d: number
): void {
  state[a]! += state[b]!;
  state[d]! ^= state[a]!;
  state[d] = ((state[d]! << 16) | (state[d]! >>> 16)) >>> 0;

  state[c]! += state[d]!;
  state[b]! ^= state[c]!;
  state[b] = ((state[b]! << 12) | (state[b]! >>> 20)) >>> 0;

  state[a]! += state[b]!;
  state[d]! ^= state[a]!;
  state[d] = ((state[d]! << 8) | (state[d]! >>> 24)) >>> 0;

  state[c]! += state[d]!;
  state[b]! ^= state[c]!;
  state[b] = ((state[b]! << 7) | (state[b]! >>> 25)) >>> 0;
}

/**
 * ChaCha20 block function.
 */
function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const state = new Uint32Array(16);

  // Constants: "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  // Key
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) {
    state[4 + i] = keyView.getUint32(i * 4, true);
  }

  // Counter
  state[12] = counter;

  // Nonce
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  state[13] = nonceView.getUint32(0, true);
  state[14] = nonceView.getUint32(4, true);
  state[15] = nonceView.getUint32(8, true);

  const working = new Uint32Array(state);

  // 20 rounds (10 double rounds)
  for (let i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    // Diagonal rounds
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  // Add original state
  for (let i = 0; i < 16; i++) {
    working[i] = (working[i]! + state[i]!) >>> 0;
  }

  // Serialize to bytes (little-endian)
  const output = new Uint8Array(64);
  const outView = new DataView(output.buffer);
  for (let i = 0; i < 16; i++) {
    outView.setUint32(i * 4, working[i]!, true);
  }

  return output;
}

/**
 * ChaCha20 stream cipher.
 */
function chacha20Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  counter: number = 1
): Uint8Array {
  const output = new Uint8Array(plaintext.length);
  let blockCounter = counter;

  for (let i = 0; i < plaintext.length; i += 64) {
    const block = chacha20Block(key, blockCounter, nonce);
    const remaining = Math.min(64, plaintext.length - i);
    for (let j = 0; j < remaining; j++) {
      output[i + j] = plaintext[i + j]! ^ block[j]!;
    }
    blockCounter++;
  }

  return output;
}

/**
 * Poly1305 MAC.
 */
function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Clamp r
  const rBytes = new Uint8Array([
    key[0]!,
    key[1]!,
    key[2]!,
    key[3]! & 0x0f,
    key[4]! & 0xfc,
    key[5]!,
    key[6]!,
    key[7]! & 0x0f,
    key[8]! & 0xfc,
    key[9]!,
    key[10]!,
    key[11]! & 0x0f,
    key[12]! & 0xfc,
    key[13]!,
    key[14]!,
    key[15]! & 0x0f,
  ]);
  const rHex = bytesToHex(new Uint8Array([...rBytes].reverse()));
  const r = BigInt('0x' + rHex);

  const sBytes = new Uint8Array([
    key[16]!,
    key[17]!,
    key[18]!,
    key[19]!,
    key[20]!,
    key[21]!,
    key[22]!,
    key[23]!,
    key[24]!,
    key[25]!,
    key[26]!,
    key[27]!,
    key[28]!,
    key[29]!,
    key[30]!,
    key[31]!,
  ]);
  const sHex = bytesToHex(new Uint8Array([...sBytes].reverse()));
  const s = BigInt('0x' + sHex);

  const p = (BigInt(1) << BigInt(130)) - BigInt(5);
  let accumulator = BigInt(0);

  for (let i = 0; i < message.length; i += 16) {
    const end = Math.min(i + 16, message.length);
    const chunk = message.slice(i, end);
    // Convert to little-endian number and add high bit
    const bytes = new Uint8Array(end - i + 1);
    bytes.set(chunk);
    bytes[end - i] = 1;
    let n = BigInt(0);
    for (let j = bytes.length - 1; j >= 0; j--) {
      n = (n << BigInt(8)) | BigInt(bytes[j]!);
    }
    accumulator = (accumulator + n) % p;
    accumulator = (accumulator * r) % p;
  }

  accumulator = (accumulator + s) % (BigInt(1) << BigInt(128));

  // Convert to 16 bytes little-endian
  const result = new Uint8Array(16);
  let temp = accumulator;
  for (let i = 0; i < 16; i++) {
    result[i] = Number(temp & BigInt(0xff));
    temp >>= BigInt(8);
  }

  return result;
}

/**
 * Pad data to 16-byte boundary for Poly1305 AEAD construction.
 */
function pad16(data: Uint8Array): Uint8Array {
  if (data.length % 16 === 0) return data;
  const padding = 16 - (data.length % 16);
  return concatBytes(data, new Uint8Array(padding));
}

/**
 * Little-endian 8-byte length encoding.
 */
function leLen(len: number): Uint8Array {
  const result = new Uint8Array(8);
  const view = new DataView(result.buffer);
  view.setUint32(0, len, true);
  view.setUint32(4, 0, true);
  return result;
}

/**
 * ChaCha20-Poly1305 AEAD encrypt.
 */
export function chacha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  // Generate Poly1305 key
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);

  // Encrypt
  const ciphertext = chacha20Encrypt(key, nonce, plaintext, 1);

  // Compute MAC
  const macInput = concatBytes(
    pad16(aad),
    pad16(ciphertext),
    leLen(aad.length),
    leLen(ciphertext.length)
  );
  const tag = poly1305Mac(polyKey, macInput);

  return concatBytes(ciphertext, tag);
}

/**
 * ChaCha20-Poly1305 AEAD decrypt.
 */
export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (ciphertextWithTag.length < 16) {
    throw new Error('Ciphertext too short');
  }

  const ciphertext = ciphertextWithTag.slice(0, -16);
  const tag = ciphertextWithTag.slice(-16);

  // Generate Poly1305 key
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);

  // Verify MAC
  const macInput = concatBytes(
    pad16(aad),
    pad16(ciphertext),
    leLen(aad.length),
    leLen(ciphertext.length)
  );
  const expectedTag = poly1305Mac(polyKey, macInput);

  // Constant-time comparison
  let diff = 0;
  for (let i = 0; i < 16; i++) {
    diff |= tag[i]! ^ expectedTag[i]!;
  }
  if (diff !== 0) {
    throw new Error('Authentication failed: invalid tag');
  }

  // Decrypt
  return chacha20Encrypt(key, nonce, ciphertext, 1);
}

// ─── MIP-01: Image Upload Identity ─────────────────────────────────────────

/**
 * Derive the Blossom upload keypair from image_key.
 * upload_secret = HKDF-Expand(image_key, "mip01-blossom-upload-v1", 32)
 */
export function deriveUploadKeypair(imageKey: Uint8Array): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  const uploadSecret = hkdfExpand(imageKey, 'mip01-blossom-upload-v1', 32);
  return keypairFromSecret(uploadSecret);
}
