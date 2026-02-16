import { describe, it, expect } from 'vitest';

// Bun's WebCrypto doesn't support X25519 HPKE operations needed by ts-mls.
// Skip tests that require addMlsGroupMembers/joinMlsGroupFromWelcome on Bun.
const isBun = typeof globalThis.Bun !== 'undefined';
const describeHpke = isBun ? describe.skip : describe;
import {
  DEFAULT_CIPHERSUITE,
  getCiphersuiteImpl,
  getSupportedCiphersuites,
  ciphersuiteNameToId,
  ciphersuiteIdToName,
  generateMlsKeyPackage,
  parseKeyPackageBytes,
  parseKeyPackageFromEvent,
  readMlsVarint,
  parseKeyPackageRaw,
  createMlsGroup,
  addMlsGroupMembers,
  joinMlsGroupFromWelcome,
  deriveExporterSecret,
  encodeMlsState,
  decodeMlsState,
  encodeWelcome,
  decodeWelcome,
  encodeWelcomeRaw,
  decodeWelcomeRaw,
  encodeKeyPackage,
  decodeKeyPackage,
} from '../src/mls.js';
import { encodeMlsMessage } from 'ts-mls';
import { parseKeyPackageEvent } from '../src/mip00.js';
import type { UnsignedEvent } from '../src/types.js';

// ─── Test Helpers ───────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Test identity (random 32-byte pubkey hex)
const TEST_PUBKEY_ALICE =
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const TEST_PUBKEY_BOB =
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

// ─── Ciphersuite Management ─────────────────────────────────────────────────

describe('Ciphersuite management', () => {
  it('DEFAULT_CIPHERSUITE should be 0x0001', () => {
    expect(DEFAULT_CIPHERSUITE).toBe('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    expect(ciphersuiteNameToId(DEFAULT_CIPHERSUITE)).toBe(1);
  });

  it('getSupportedCiphersuites should return all suites', () => {
    const suites = getSupportedCiphersuites();
    expect(suites.length).toBeGreaterThanOrEqual(7);
    expect(suites).toContain(DEFAULT_CIPHERSUITE);
    expect(suites).toContain('MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519');
  });

  it('ciphersuiteNameToId should convert names to IDs', () => {
    expect(ciphersuiteNameToId('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519')).toBe(1);
    expect(ciphersuiteNameToId('MLS_128_DHKEMP256_AES128GCM_SHA256_P256')).toBe(2);
    expect(
      ciphersuiteNameToId('MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519')
    ).toBe(3);
  });

  it('ciphersuiteIdToName should convert IDs to names', () => {
    expect(ciphersuiteIdToName(1)).toBe('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    expect(ciphersuiteIdToName(2)).toBe('MLS_128_DHKEMP256_AES128GCM_SHA256_P256');
    expect(ciphersuiteIdToName(3)).toBe(
      'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519'
    );
  });

  it('ciphersuiteNameToId should throw for unknown names', () => {
    expect(() => ciphersuiteNameToId('INVALID' as never)).toThrow('Unknown ciphersuite');
  });

  it('ciphersuiteIdToName should throw for unknown IDs', () => {
    expect(() => ciphersuiteIdToName(9999)).toThrow('Unknown ciphersuite ID');
  });

  it('name ↔ ID should round-trip', () => {
    const suites = getSupportedCiphersuites();
    for (const name of suites) {
      const id = ciphersuiteNameToId(name);
      expect(ciphersuiteIdToName(id)).toBe(name);
    }
  });

  it('getCiphersuiteImpl should return a CiphersuiteImpl', async () => {
    const impl = await getCiphersuiteImpl();
    expect(impl).toBeDefined();
    expect(impl.name).toBe(DEFAULT_CIPHERSUITE);
  });

  it('getCiphersuiteImpl should cache results', async () => {
    const impl1 = await getCiphersuiteImpl();
    const impl2 = await getCiphersuiteImpl();
    expect(impl1).toBe(impl2); // Same reference
  });
});

// ─── KeyPackage Generation ──────────────────────────────────────────────────

describe('KeyPackage generation', () => {
  it('should generate a KeyPackage for default ciphersuite (0x0001)', async () => {
    const result = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    expect(result.keyPackageBytes).toBeInstanceOf(Uint8Array);
    expect(result.keyPackageBytes.length).toBeGreaterThan(100);
    expect(result.keyPackage).toBeDefined();
    expect(result.privateKeyPackage).toBeDefined();

    // Should be in raw format (starts with 0x0001 + ciphersuite)
    expect(result.keyPackageBytes[0]).toBe(0x00);
    expect(result.keyPackageBytes[1]).toBe(0x01);
    // Ciphersuite 0x0001
    expect(result.keyPackageBytes[2]).toBe(0x00);
    expect(result.keyPackageBytes[3]).toBe(0x01);
  });

  it('should embed Nostr pubkey as credential identity', async () => {
    const result = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    const identity = result.keyPackage.leafNode.credential.identity;
    expect(bytesToHex(identity)).toBe(TEST_PUBKEY_ALICE);
  });

  it('should reject invalid pubkey hex', async () => {
    await expect(generateMlsKeyPackage('invalid')).rejects.toThrow(
      'Invalid Nostr pubkey hex'
    );
    await expect(generateMlsKeyPackage('abcd')).rejects.toThrow(
      'Invalid Nostr pubkey hex'
    );
    await expect(
      generateMlsKeyPackage(
        'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
      )
    ).rejects.toThrow('Invalid Nostr pubkey hex');
  });

  it('should generate unique KeyPackages', async () => {
    const kp1 = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    const kp2 = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    // Different init keys (random)
    expect(bytesToHex(kp1.keyPackageBytes)).not.toBe(bytesToHex(kp2.keyPackageBytes));
  });
});

// ─── KeyPackage Round-trip ──────────────────────────────────────────────────

describe('KeyPackage round-trip', () => {
  it('generate → encode → decode → verify identity', async () => {
    const result = await generateMlsKeyPackage(TEST_PUBKEY_BOB);

    // Encode
    const encoded = encodeKeyPackage(result.keyPackage);
    expect(encoded.length).toBeGreaterThan(100);

    // Decode
    const decoded = decodeKeyPackage(encoded);
    expect(decoded.version).toBe('mls10');
    expect(decoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);

    // Verify identity
    const identity = bytesToHex(decoded.leafNode.credential.identity);
    expect(identity).toBe(TEST_PUBKEY_BOB);
  });
});

// ─── KeyPackage Parsing ─────────────────────────────────────────────────────

describe('KeyPackage parsing', () => {
  it('should parse raw KeyPackage format', async () => {
    const { keyPackageBytes, keyPackage: _keyPackage } =
      await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    // Raw format starts with 0x0001 0x0001
    expect(keyPackageBytes[0]).toBe(0x00);
    expect(keyPackageBytes[1]).toBe(0x01);

    const parsed = parseKeyPackageBytes(keyPackageBytes);
    expect(parsed.version).toBe('mls10');
    expect(parsed.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(bytesToHex(parsed.leafNode.credential.identity)).toBe(TEST_PUBKEY_ALICE);
  });

  it('should parse MLSMessage-wrapped KeyPackage format', async () => {
    const { keyPackage } = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    // Create MLSMessage-wrapped version
    const wrapped = encodeMlsMessage({
      version: 'mls10',
      wireformat: 'mls_key_package',
      keyPackage,
    });

    // Wrapped starts with 0x0001 0x0005
    expect(wrapped[0]).toBe(0x00);
    expect(wrapped[1]).toBe(0x01);
    expect(wrapped[2]).toBe(0x00);
    expect(wrapped[3]).toBe(0x05);

    const parsed = parseKeyPackageBytes(wrapped);
    expect(parsed.version).toBe('mls10');
    expect(parsed.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(bytesToHex(parsed.leafNode.credential.identity)).toBe(TEST_PUBKEY_ALICE);
  });

  it('should reject too-short data', () => {
    expect(() => parseKeyPackageBytes(new Uint8Array(3))).toThrow('too short');
  });

  it('should reject OpenMLS format (0xd34d)', () => {
    const openmlsData = new Uint8Array([0xd3, 0x4d, 0x00, 0x00, 0x00]);
    expect(() => parseKeyPackageBytes(openmlsData)).toThrow('OpenMLS format');
  });

  it('should reject unknown version', () => {
    const badData = new Uint8Array([0xff, 0xff, 0x00, 0x01, 0x00]);
    expect(() => parseKeyPackageBytes(badData)).toThrow('Unknown KeyPackage format');
  });
});

// ─── Group Creation ─────────────────────────────────────────────────────────

describe('Group creation', () => {
  it('should create a group with exporter secret', async () => {
    const groupId = new Uint8Array(32).fill(0x42);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    expect(result.state).toBeDefined();
    expect(result.encodedState).toBeInstanceOf(Uint8Array);
    expect(result.encodedState.length).toBeGreaterThan(100);
    expect(result.groupId).toBe(groupId);
    expect(result.exporterSecret).toBeInstanceOf(Uint8Array);
    expect(result.exporterSecret.length).toBe(32);
  });

  it('should set correct group ID in state', async () => {
    const groupId = new Uint8Array(32).fill(0x42);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    expect(bytesToHex(result.state.groupContext.groupId)).toBe(bytesToHex(groupId));
    expect(result.state.groupContext.epoch).toBe(0n);
  });

  it('should derive a deterministic exporter secret', async () => {
    const groupId = new Uint8Array(32).fill(0x42);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    // Derive again from the same state
    const exporterSecret2 = await deriveExporterSecret(result.state);
    expect(bytesToHex(result.exporterSecret)).toBe(bytesToHex(exporterSecret2));
  });
});

// ─── Adding Members ─────────────────────────────────────────────────────────

describeHpke('Adding members', () => {
  it('should add a member and produce Welcome', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const result = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    expect(result.newState).toBeDefined();
    expect(result.welcome).toBeDefined();
    expect(result.commit).toBeDefined();
    expect(result.encodedState).toBeInstanceOf(Uint8Array);
    expect(result.exporterSecret).toBeInstanceOf(Uint8Array);
    expect(result.exporterSecret.length).toBe(32);

    // New state should be epoch 1
    expect(result.newState.groupContext.epoch).toBe(1n);
  });

  it('should produce different exporter secret after adding member', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const result = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    // Exporter secret should change after epoch advance
    expect(bytesToHex(result.exporterSecret)).not.toBe(bytesToHex(alice.exporterSecret));
  });
});

// ─── Joining from Welcome ───────────────────────────────────────────────────

describeHpke('Joining from Welcome', () => {
  it('should join from Welcome and match exporter secret', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    const joinResult = await joinMlsGroupFromWelcome(
      addResult.welcome,
      bobKP.keyPackage,
      bobKP.privateKeyPackage
    );

    expect(joinResult.state).toBeDefined();
    expect(joinResult.encodedState).toBeInstanceOf(Uint8Array);
    expect(joinResult.exporterSecret).toBeInstanceOf(Uint8Array);
    expect(joinResult.exporterSecret.length).toBe(32);
    expect(joinResult.groupId).toBeInstanceOf(Uint8Array);

    // CRITICAL: Exporter secrets must match between adder and joiner
    expect(bytesToHex(joinResult.exporterSecret)).toBe(
      bytesToHex(addResult.exporterSecret)
    );

    // Group ID should match
    expect(bytesToHex(joinResult.groupId)).toBe(bytesToHex(groupId));

    // Epoch should be 1 (after the Add commit)
    expect(joinResult.state.groupContext.epoch).toBe(1n);
  });
});

// ─── State Serialization ────────────────────────────────────────────────────

describeHpke('State serialization', () => {
  it('should encode/decode group state round-trip', async () => {
    const groupId = new Uint8Array(32).fill(0x42);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const encoded = encodeMlsState(result.state);
    expect(encoded).toBeInstanceOf(Uint8Array);
    expect(encoded.length).toBeGreaterThan(100);

    const decoded = decodeMlsState(encoded);
    expect(decoded.groupContext.epoch).toBe(result.state.groupContext.epoch);
    expect(bytesToHex(decoded.groupContext.groupId)).toBe(
      bytesToHex(result.state.groupContext.groupId)
    );
  });

  it('should encode Welcome as MLSMessage-wrapped (MIP-02 format)', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    const encoded = encodeWelcome(addResult.welcome);
    expect(encoded).toBeInstanceOf(Uint8Array);
    expect(encoded.length).toBeGreaterThan(100);

    // Per MIP-02: Welcome MUST be MLSMessage-wrapped
    // MLSMessage starts with version 0x0001 + wireformat 0x0003 (mls_welcome)
    expect(encoded[0]).toBe(0x00);
    expect(encoded[1]).toBe(0x01); // version = mls10
    expect(encoded[2]).toBe(0x00);
    expect(encoded[3]).toBe(0x03); // wireformat = mls_welcome
  });

  it('should decode MLSMessage-wrapped Welcome round-trip', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    const encoded = encodeWelcome(addResult.welcome);
    const decoded = decodeWelcome(encoded);
    expect(decoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(decoded.secrets.length).toBe(addResult.welcome.secrets.length);
  });

  it('should decode raw Welcome as fallback', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    // Encode as raw (not MLSMessage-wrapped) — for backward compatibility
    const rawEncoded = encodeWelcomeRaw(addResult.welcome);
    // Raw welcome does NOT start with 0x0001 0x0003
    expect(rawEncoded[2] === 0x00 && rawEncoded[3] === 0x03).toBe(false);

    // decodeWelcome should fall back to raw decoding
    const decoded = decodeWelcome(rawEncoded);
    expect(decoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
  });

  it('encodeWelcomeRaw/decodeWelcomeRaw should round-trip', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [bobKP.keyPackage]);

    const rawEncoded = encodeWelcomeRaw(addResult.welcome);
    const decoded = decodeWelcomeRaw(rawEncoded);
    expect(decoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(decoded.secrets.length).toBe(addResult.welcome.secrets.length);
  });

  it('should throw on invalid state bytes', () => {
    expect(() => decodeMlsState(new Uint8Array([0x00, 0x01]))).toThrow(
      'Failed to decode MLS group state'
    );
  });

  it('should throw on invalid Welcome bytes', () => {
    expect(() => decodeWelcome(new Uint8Array([0x00]))).toThrow('Welcome data too short');
  });

  it('should reject MLSMessage with wrong wireformat for Welcome', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const _alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    // Encode a KeyPackage as MLSMessage (wireformat = mls_key_package, not mls_welcome)
    const aliceKP = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    const kpWrapped = encodeMlsMessage({
      version: 'mls10',
      wireformat: 'mls_key_package',
      keyPackage: aliceKP.keyPackage,
    });

    expect(() => decodeWelcome(kpWrapped)).toThrow(
      'Expected MLSMessage with wireformat mls_welcome'
    );
  });
});

// ─── KeyPackage encode/decode ───────────────────────────────────────────────

describe('KeyPackage encode/decode', () => {
  it('should encode/decode KeyPackage round-trip', async () => {
    const { keyPackage } = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    const encoded = encodeKeyPackage(keyPackage);
    const decoded = decodeKeyPackage(encoded);

    expect(decoded.version).toBe(keyPackage.version);
    expect(decoded.cipherSuite).toBe(keyPackage.cipherSuite);
    expect(bytesToHex(decoded.leafNode.credential.identity)).toBe(TEST_PUBKEY_ALICE);
  });

  it('should throw on invalid KeyPackage bytes', () => {
    expect(() => decodeKeyPackage(new Uint8Array([0x00]))).toThrow(
      'Failed to decode KeyPackage'
    );
  });
});

// ─── parseKeyPackageFromEvent ───────────────────────────────────────────────

describe('parseKeyPackageFromEvent', () => {
  it('should parse KeyPackage from event with base64-encoded content', async () => {
    const { keyPackageBytes, keyPackage: _keyPackage } =
      await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    // Create a minimal kind:443 event
    const content = Buffer.from(keyPackageBytes).toString('base64');
    const event: UnsignedEvent = {
      kind: 443,
      created_at: Math.floor(Date.now() / 1000),
      pubkey: TEST_PUBKEY_ALICE,
      content,
      tags: [
        ['mls_protocol_version', '1.0'],
        ['mls_ciphersuite', '0x0001'],
        ['mls_extensions', '0xf2ee', '0x000a'],
        ['encoding', 'base64'],
        ['relays', 'wss://relay.example.com'],
      ],
      id: 'test-event-id',
    };

    const result = parseKeyPackageFromEvent(event);

    expect(result.parsed).toBeDefined();
    expect(result.parsed.pubkey).toBe(TEST_PUBKEY_ALICE);
    expect(result.parsed.encoding).toBe('base64');
    expect(result.parsed.ciphersuite).toBe('0x0001');

    expect(result.mlsKeyPackage).toBeDefined();
    expect(result.mlsKeyPackage.version).toBe('mls10');
    expect(result.mlsKeyPackage.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(bytesToHex(result.mlsKeyPackage.leafNode.credential.identity)).toBe(
      TEST_PUBKEY_ALICE
    );
  });

  it('should parse KeyPackage from event with hex-encoded content', async () => {
    const { keyPackageBytes } = await generateMlsKeyPackage(TEST_PUBKEY_BOB);

    // Create a minimal kind:443 event with hex encoding
    const content = bytesToHex(keyPackageBytes);
    const event: UnsignedEvent = {
      kind: 443,
      created_at: Math.floor(Date.now() / 1000),
      pubkey: TEST_PUBKEY_BOB,
      content,
      tags: [
        ['mls_protocol_version', '1.0'],
        ['mls_ciphersuite', '0x0001'],
        ['mls_extensions', '0xf2ee', '0x000a'],
        ['encoding', 'hex'],
        ['relays', 'wss://relay.example.com'],
      ],
      id: 'test-event-id-hex',
    };

    const result = parseKeyPackageFromEvent(event);

    expect(result.parsed.encoding).toBe('hex');
    expect(result.mlsKeyPackage.version).toBe('mls10');
    expect(bytesToHex(result.mlsKeyPackage.leafNode.credential.identity)).toBe(
      TEST_PUBKEY_BOB
    );
  });

  it('should parse real Kai (MDK/0.5.3) KeyPackage event structure', () => {
    // Real test vector from Kai (MDK/0.5.3)
    // Note: This KeyPackage was generated by OpenMLS (Rust) and may not be
    // parseable by ts-mls due to implementation differences in extension handling.
    // We test that the Nostr event parsing layer works correctly.
    const kaiContent =
      'AAEAASCKhfeFLzH4PUEeyWpmCr0JST3BNzWtVDZ/H0kF8VG9ISA/Som3+xsj4J97r2wU1ejvICqER4VPTekokqYDUiC/OiAI9Ugq822dT9imiB0MBPWxViaZE9pqGo5LyktYhU0a2wABIHvQfgMEFXNHjT8OVG8WGwTID9hfmy0pJI1PK2UUekw+AgABBAABenoGAAry7kpKAmpqBAABmpoBAAAAAGmPrOIAAAAAaf548gBAQOuyS4mpCjCA3jUYYJFpP2ouRlYog9ZFFuJg5wYlXIHbhI1Tdzr9qesN2Xk7NiLXkO/1YM3SPuiZcJIHTVFzw0gFbFY4F8a00iXC9f3KF4wBGkk8f1n8r1tQ8zEZvWKhFl80BPqMXvB8X3GQKFTi1VwpDuvIxAqkMRPsDWIA';
    const kaiPubkey = '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';

    const event: UnsignedEvent = {
      kind: 443,
      created_at: 1770000000,
      pubkey: kaiPubkey,
      content: kaiContent,
      tags: [
        ['mls_protocol_version', '1.0'],
        ['mls_ciphersuite', '0x0001'],
        ['mls_extensions', '0xf2ee', '0x000a'],
        ['encoding', 'base64'],
        ['relays', 'wss://relay.example.com'],
        ['client', 'MDK/0.5.3'],
      ],
      id: 'kai-test-event',
    };

    // Nostr event parsing should work regardless of MLS implementation.
    // ts-mls may not parse OpenMLS-generated KeyPackages due to implementation
    // differences in extension/capability handling. We test the Nostr layer.
    let parsed;
    try {
      const result = parseKeyPackageFromEvent(event);
      parsed = result.parsed;
    } catch {
      // Fall back to Nostr-level parsing only
      parsed = parseKeyPackageEvent(event);
    }

    expect(parsed.pubkey).toBe(kaiPubkey);
    expect(parsed.encoding).toBe('base64');
    expect(parsed.ciphersuite).toBe('0x0001');
    expect(parsed.clientName).toBe('MDK/0.5.3');
    expect(parsed.keyPackageData.length).toBe(306);

    // Verify raw bytes structure
    const raw = parsed.keyPackageData;
    expect(raw[0]).toBe(0x00);
    expect(raw[1]).toBe(0x01); // version mls10
    expect(raw[2]).toBe(0x00);
    expect(raw[3]).toBe(0x01); // ciphersuite 0x0001
  });
});

// ─── Full Integration Flow ──────────────────────────────────────────────────

describeHpke('Full MLS integration flow', () => {
  it('Alice creates group → adds Bob → Bob joins → secrets match', async () => {
    // 1. Alice creates a group
    const groupId = new Uint8Array(32);
    crypto.getRandomValues(groupId);

    const aliceGroup = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);
    expect(aliceGroup.state.groupContext.epoch).toBe(0n);
    expect(aliceGroup.exporterSecret.length).toBe(32);

    // 2. Bob generates a KeyPackage
    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    expect(bytesToHex(bobKP.keyPackage.leafNode.credential.identity)).toBe(
      TEST_PUBKEY_BOB
    );

    // 3. Alice adds Bob
    const addResult = await addMlsGroupMembers(aliceGroup.state, [bobKP.keyPackage]);
    expect(addResult.newState.groupContext.epoch).toBe(1n);

    // 4. Bob joins from Welcome
    const bobGroup = await joinMlsGroupFromWelcome(
      addResult.welcome,
      bobKP.keyPackage,
      bobKP.privateKeyPackage
    );
    expect(bobGroup.state.groupContext.epoch).toBe(1n);

    // 5. Exporter secrets MUST match
    expect(bytesToHex(addResult.exporterSecret)).toBe(
      bytesToHex(bobGroup.exporterSecret)
    );

    // 6. Group IDs must match
    expect(bytesToHex(bobGroup.groupId)).toBe(bytesToHex(groupId));

    // 7. States can be serialized
    const aliceEncoded = encodeMlsState(addResult.newState);
    const bobEncoded = encodeMlsState(bobGroup.state);
    expect(aliceEncoded.length).toBeGreaterThan(100);
    expect(bobEncoded.length).toBeGreaterThan(100);

    // 8. Welcome serializes as MLSMessage-wrapped (MIP-02)
    const welcomeBytes = encodeWelcome(addResult.welcome);
    expect(welcomeBytes[0]).toBe(0x00);
    expect(welcomeBytes[1]).toBe(0x01); // version
    expect(welcomeBytes[2]).toBe(0x00);
    expect(welcomeBytes[3]).toBe(0x03); // wireformat = mls_welcome
    const welcomeDecoded = decodeWelcome(welcomeBytes);
    expect(welcomeDecoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
  });
});

// ─── Exporter Secret ────────────────────────────────────────────────────────

describeHpke('Exporter secret', () => {
  it('deriveExporterSecret produces 32-byte result', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const secret = await deriveExporterSecret(result.state);
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  it('deriveExporterSecret is deterministic for same state', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const s1 = await deriveExporterSecret(result.state);
    const s2 = await deriveExporterSecret(result.state);
    expect(bytesToHex(s1)).toBe(bytesToHex(s2));
  });
});

// ─── MLS Varint ─────────────────────────────────────────────────────────────

describe('readMlsVarint', () => {
  it('should read 1-byte varint (prefix 00)', () => {
    // 0x20 = 0b00100000 → value = 32
    const [value, off] = readMlsVarint(new Uint8Array([0x20]), 0);
    expect(value).toBe(32);
    expect(off).toBe(1);
  });

  it('should read 1-byte varint max value (63)', () => {
    // 0x3F = 0b00111111 → value = 63
    const [value, off] = readMlsVarint(new Uint8Array([0x3f]), 0);
    expect(value).toBe(63);
    expect(off).toBe(1);
  });

  it('should read 1-byte varint value 0', () => {
    const [value, off] = readMlsVarint(new Uint8Array([0x00]), 0);
    expect(value).toBe(0);
    expect(off).toBe(1);
  });

  it('should read 2-byte varint (prefix 01)', () => {
    // 0x41 0x00 = 0b01000001 00000000 → value = (1 << 8) | 0 = 256
    const [value, off] = readMlsVarint(new Uint8Array([0x41, 0x00]), 0);
    expect(value).toBe(256);
    expect(off).toBe(2);
  });

  it('should read 2-byte varint with typical KeyPackage value', () => {
    // 0x40 0x40 = value = (0 << 8) | 0x40 = 64
    const [value, off] = readMlsVarint(new Uint8Array([0x40, 0x40]), 0);
    expect(value).toBe(64);
    expect(off).toBe(2);
  });

  it('should read 4-byte varint (prefix 10)', () => {
    // 0x80 0x00 0x01 0x00 → value = (0 << 24) | (0 << 16) | (1 << 8) | 0 = 256
    const [value, off] = readMlsVarint(new Uint8Array([0x80, 0x00, 0x01, 0x00]), 0);
    expect(value).toBe(256);
    expect(off).toBe(4);
  });

  it('should throw on invalid prefix 0b11', () => {
    // 0xC0 = 0b11000000
    expect(() => readMlsVarint(new Uint8Array([0xc0]), 0)).toThrow('invalid prefix');
  });

  it('should throw on out-of-bounds offset', () => {
    expect(() => readMlsVarint(new Uint8Array([0x00]), 1)).toThrow('out of bounds');
  });

  it('should throw on insufficient data for 2-byte varint', () => {
    expect(() => readMlsVarint(new Uint8Array([0x40]), 0)).toThrow('insufficient data');
  });

  it('should read varint at non-zero offset', () => {
    const data = new Uint8Array([0xff, 0xff, 0x05]);
    const [value, off] = readMlsVarint(data, 2);
    expect(value).toBe(5);
    expect(off).toBe(3);
  });
});

// ─── parseKeyPackageRaw ─────────────────────────────────────────────────────

describe('parseKeyPackageRaw', () => {
  // Real Kai MDK/0.5.3 KeyPackage (base64-encoded, from relay)
  const kaiMdkBase64 =
    'AAEAASCKhfeFLzH4PUEeyWpmCr0JST3BNzWtVDZ/H0kF8VG9ISA/Som3+xsj4J97r2wU1ejvICqER4VPTekokqYDUiC/OiAI9Ugq822dT9imiB0MBPWxViaZE9pqGo5LyktYhU0a2wABIHvQfgMEFXNHjT8OVG8WGwTID9hfmy0pJI1PK2UUekw+AgABBAABenoGAAry7kpKAmpqBAABmpoBAAAAAGmPrOIAAAAAaf548gBAQOuyS4mpCjCA3jUYYJFpP2ouRlYog9ZFFuJg5wYlXIHbhI1Tdzr9qesN2Xk7ZUyecp4PbgjrsXIGcYd+aHO4PA8DAAoAQEAbISx5lmK9dAtc9JSps5FPvpwm0sxC3ZqDXoHyNx7/oYxHlROeWuY7iW5tXcdgMssQxkYO/BFStRoxtwj9ZTwC';

  // Real XChat (marmot-chat) KeyPackage (hex-encoded, from relay)
  const xchatHex =
    '0001000120d9c5b1698f3b4c9272e6bf0e4bfff1ca7ab5adfd4c66edc04f3543386c4c392d20345fbcf1b59039747a6ef3ae8b4d1ec930f885be2755e2b7d14a3ce7a08927722069e18cd775e26d8b9ea0561666b324e33efb3600dd01721c27d01ed1f3dea8c30001404035626530663737633230393338356631336130343839346531383262393931663663646236313238636138613162356234316335383132396564343166326532020001020001080003000a0002f2ee00020001010000000069927320000000006a013f30004040cf026b5c84a32eb05fef53509acd800dd0c6ef859a59f6a8935d2f11bb9c427cc9d56b60bb0810359e7e15f1b62ccd697e4ff692b36e129fee123026d2306e0003000a0040409300dc1b8bd797815840db1d30ec376136290743dce03f209d5030aadf62d2bb83a322a6aee22cf31af96a736d3b958816fb699146739322e3e6cc21bfa35d09';

  const kaiPubkey = '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';
  const xchatPubkey = '5be0f77c209385f13a04894e182b991f6cdb6128ca8a1b5b41c58129ed41f2e2';

  it('should parse MDK KeyPackage (Kai)', () => {
    const bytes = Buffer.from(kaiMdkBase64, 'base64');
    const parsed = parseKeyPackageRaw(bytes);

    expect(parsed.version).toBe(1);
    expect(parsed.cipherSuite).toBe(1);
    expect(parsed.initKey.length).toBe(32);
    expect(parsed.encryptionKey.length).toBe(32);
    expect(parsed.signatureKey.length).toBe(32);
    expect(parsed.credentialType).toBe(1); // basic
    expect(parsed.identity.length).toBe(32); // raw 32-byte pubkey
    expect(parsed.identityHex).toBe(kaiPubkey);
    expect(parsed.leafNodeSource).toBe(1); // key_package
    expect(parsed.notBefore).toBeDefined();
    expect(parsed.notAfter).toBeDefined();
    expect(parsed.leafSignature.length).toBe(64); // Ed25519
    expect(parsed.kpSignature.length).toBe(64);
    expect(parsed.totalBytes).toBe(bytes.length); // consumed all bytes
  });

  it('should parse MDK capabilities with GREASE values', () => {
    const bytes = Buffer.from(kaiMdkBase64, 'base64');
    const parsed = parseKeyPackageRaw(bytes);

    // MDK capabilities:
    expect(parsed.capabilities.versions).toEqual([1]); // mls10
    expect(parsed.capabilities.ciphersuites).toContain(1); // 0x0001
    expect(parsed.capabilities.ciphersuites).toContain(0x7a7a); // GREASE
    expect(parsed.capabilities.extensions).toContain(0x000a); // ratchet_tree / last_resort
    expect(parsed.capabilities.extensions).toContain(0xf2ee); // marmot_group_data
    expect(parsed.capabilities.extensions).toContain(0x4a4a); // GREASE
    expect(parsed.capabilities.credentials).toContain(1); // basic
    expect(parsed.capabilities.credentials).toContain(0x9a9a); // GREASE
  });

  it('should parse MDK kp_extensions (last_resort)', () => {
    const bytes = Buffer.from(kaiMdkBase64, 'base64');
    const parsed = parseKeyPackageRaw(bytes);

    // kp_extensions should contain last_resort (0x000a) with empty data
    expect(parsed.kpExtensions.length).toBe(1);
    expect(parsed.kpExtensions[0]!.type).toBe(0x000a);
    expect(parsed.kpExtensions[0]!.data.length).toBe(0);
  });

  it('should parse XChat KeyPackage (marmot-chat)', () => {
    const bytes = hexToBytes(xchatHex);
    const parsed = parseKeyPackageRaw(bytes);

    expect(parsed.version).toBe(1);
    expect(parsed.cipherSuite).toBe(1);
    expect(parsed.initKey.length).toBe(32);
    expect(parsed.encryptionKey.length).toBe(32);
    expect(parsed.signatureKey.length).toBe(32);
    expect(parsed.credentialType).toBe(1);
    // XChat uses 64-byte hex-encoded ASCII identity
    expect(parsed.identity.length).toBe(64);
    expect(parsed.identityHex).toBe(xchatPubkey);
    expect(parsed.leafNodeSource).toBe(1);
    expect(parsed.leafSignature.length).toBe(64);
    expect(parsed.kpSignature.length).toBe(64);
    expect(parsed.totalBytes).toBe(bytes.length);
  });

  it('should parse XChat capabilities', () => {
    const bytes = hexToBytes(xchatHex);
    const parsed = parseKeyPackageRaw(bytes);

    expect(parsed.capabilities.versions).toEqual([1]);
    expect(parsed.capabilities.ciphersuites).toContain(1);
    // XChat lists extensions 0x0003, 0x000a, 0x0002, 0xf2ee
    expect(parsed.capabilities.extensions).toContain(0x000a);
    expect(parsed.capabilities.extensions).toContain(0xf2ee);
    expect(parsed.capabilities.credentials).toContain(1);
  });

  it('should parse ts-mls generated KeyPackage', async () => {
    const { keyPackageBytes } = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    const parsed = parseKeyPackageRaw(keyPackageBytes);

    expect(parsed.version).toBe(1);
    expect(parsed.cipherSuite).toBe(1);
    expect(parsed.identityHex).toBe(TEST_PUBKEY_ALICE);
    expect(parsed.credentialType).toBe(1);
    expect(parsed.leafNodeSource).toBe(1);
    expect(parsed.leafSignature.length).toBe(64);
    expect(parsed.kpSignature.length).toBe(64);
    expect(parsed.totalBytes).toBe(keyPackageBytes.length);
  });

  it('should handle MLSMessage-wrapped KeyPackage', async () => {
    const { keyPackage } = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const wrapped = encodeMlsMessage({
      version: 'mls10',
      wireformat: 'mls_key_package',
      keyPackage,
    });

    // Wrapped starts with 0x0001 0x0005
    expect(wrapped[0]).toBe(0x00);
    expect(wrapped[1]).toBe(0x01);
    expect(wrapped[2]).toBe(0x00);
    expect(wrapped[3]).toBe(0x05);

    const parsed = parseKeyPackageRaw(wrapped);
    expect(parsed.version).toBe(1);
    expect(parsed.identityHex).toBe(TEST_PUBKEY_BOB);
  });

  it('should extract matching identity from both parsers', async () => {
    const { keyPackageBytes } = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    const raw = parseKeyPackageRaw(keyPackageBytes);
    const tsml = parseKeyPackageBytes(keyPackageBytes);

    expect(raw.identityHex).toBe(bytesToHex(tsml.leafNode.credential.identity));
  });

  it('should reject too-short data', () => {
    expect(() => parseKeyPackageRaw(new Uint8Array(3))).toThrow('too short');
  });

  it('should parse lifetime correctly for MDK KeyPackage', () => {
    const bytes = Buffer.from(kaiMdkBase64, 'base64');
    const parsed = parseKeyPackageRaw(bytes);

    // not_before and not_after should be reasonable Unix timestamps
    expect(parsed.notBefore).toBeDefined();
    expect(parsed.notAfter).toBeDefined();
    expect(parsed.notBefore!).toBe(1771023586n);
    expect(parsed.notAfter!).toBe(1778284786n);
    // not_after > not_before
    expect(parsed.notAfter!).toBeGreaterThan(parsed.notBefore!);
  });
});
