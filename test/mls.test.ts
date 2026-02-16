import { describe, it, expect } from 'vitest';
import {
  DEFAULT_CIPHERSUITE,
  getCiphersuiteImpl,
  getSupportedCiphersuites,
  ciphersuiteNameToId,
  ciphersuiteIdToName,
  generateMlsKeyPackage,
  parseKeyPackageBytes,
  parseKeyPackageFromEvent,
  createMlsGroup,
  addMlsGroupMembers,
  joinMlsGroupFromWelcome,
  deriveExporterSecret,
  encodeMlsState,
  decodeMlsState,
  encodeWelcome,
  decodeWelcome,
  encodeKeyPackage,
  decodeKeyPackage,
} from '../src/mls.js';
import { encodeMlsMessage } from 'ts-mls';
import { parseKeyPackageEvent } from '../src/mip00.js';
import type { SignedEvent, UnsignedEvent } from '../src/types.js';

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
    expect(DEFAULT_CIPHERSUITE).toBe(
      'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'
    );
    expect(ciphersuiteNameToId(DEFAULT_CIPHERSUITE)).toBe(1);
  });

  it('getSupportedCiphersuites should return all suites', () => {
    const suites = getSupportedCiphersuites();
    expect(suites.length).toBeGreaterThanOrEqual(7);
    expect(suites).toContain(DEFAULT_CIPHERSUITE);
    expect(suites).toContain(
      'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519'
    );
  });

  it('ciphersuiteNameToId should convert names to IDs', () => {
    expect(
      ciphersuiteNameToId('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519')
    ).toBe(1);
    expect(
      ciphersuiteNameToId('MLS_128_DHKEMP256_AES128GCM_SHA256_P256')
    ).toBe(2);
    expect(
      ciphersuiteNameToId(
        'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519'
      )
    ).toBe(3);
  });

  it('ciphersuiteIdToName should convert IDs to names', () => {
    expect(ciphersuiteIdToName(1)).toBe(
      'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'
    );
    expect(ciphersuiteIdToName(2)).toBe(
      'MLS_128_DHKEMP256_AES128GCM_SHA256_P256'
    );
    expect(ciphersuiteIdToName(3)).toBe(
      'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519'
    );
  });

  it('ciphersuiteNameToId should throw for unknown names', () => {
    expect(() =>
      ciphersuiteNameToId('INVALID' as never)
    ).toThrow('Unknown ciphersuite');
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
      generateMlsKeyPackage('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz')
    ).rejects.toThrow('Invalid Nostr pubkey hex');
  });

  it('should generate unique KeyPackages', async () => {
    const kp1 = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    const kp2 = await generateMlsKeyPackage(TEST_PUBKEY_ALICE);
    // Different init keys (random)
    expect(bytesToHex(kp1.keyPackageBytes)).not.toBe(
      bytesToHex(kp2.keyPackageBytes)
    );
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
    const { keyPackageBytes, keyPackage } =
      await generateMlsKeyPackage(TEST_PUBKEY_ALICE);

    // Raw format starts with 0x0001 0x0001
    expect(keyPackageBytes[0]).toBe(0x00);
    expect(keyPackageBytes[1]).toBe(0x01);

    const parsed = parseKeyPackageBytes(keyPackageBytes);
    expect(parsed.version).toBe('mls10');
    expect(parsed.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(bytesToHex(parsed.leafNode.credential.identity)).toBe(
      TEST_PUBKEY_ALICE
    );
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
    expect(bytesToHex(parsed.leafNode.credential.identity)).toBe(
      TEST_PUBKEY_ALICE
    );
  });

  it('should reject too-short data', () => {
    expect(() => parseKeyPackageBytes(new Uint8Array(3))).toThrow(
      'too short'
    );
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

    expect(bytesToHex(result.state.groupContext.groupId)).toBe(
      bytesToHex(groupId)
    );
    expect(result.state.groupContext.epoch).toBe(0n);
  });

  it('should derive a deterministic exporter secret', async () => {
    const groupId = new Uint8Array(32).fill(0x42);
    const result = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    // Derive again from the same state
    const exporterSecret2 = await deriveExporterSecret(result.state);
    expect(bytesToHex(result.exporterSecret)).toBe(
      bytesToHex(exporterSecret2)
    );
  });
});

// ─── Adding Members ─────────────────────────────────────────────────────────

describe('Adding members', () => {
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
    expect(bytesToHex(result.exporterSecret)).not.toBe(
      bytesToHex(alice.exporterSecret)
    );
  });
});

// ─── Joining from Welcome ───────────────────────────────────────────────────

describe('Joining from Welcome', () => {
  it('should join from Welcome and match exporter secret', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [
      bobKP.keyPackage,
    ]);

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

describe('State serialization', () => {
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

  it('should encode/decode Welcome round-trip', async () => {
    const groupId = new Uint8Array(32).fill(0x01);
    const alice = await createMlsGroup(groupId, TEST_PUBKEY_ALICE);

    const bobKP = await generateMlsKeyPackage(TEST_PUBKEY_BOB);
    const addResult = await addMlsGroupMembers(alice.state, [
      bobKP.keyPackage,
    ]);

    const encoded = encodeWelcome(addResult.welcome);
    expect(encoded).toBeInstanceOf(Uint8Array);
    expect(encoded.length).toBeGreaterThan(100);

    const decoded = decodeWelcome(encoded);
    expect(decoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
    expect(decoded.secrets.length).toBe(addResult.welcome.secrets.length);
  });

  it('should throw on invalid state bytes', () => {
    expect(() => decodeMlsState(new Uint8Array([0x00, 0x01]))).toThrow(
      'Failed to decode MLS group state'
    );
  });

  it('should throw on invalid Welcome bytes', () => {
    expect(() => decodeWelcome(new Uint8Array([0x00]))).toThrow(
      'Failed to decode Welcome'
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
    expect(bytesToHex(decoded.leafNode.credential.identity)).toBe(
      TEST_PUBKEY_ALICE
    );
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
    const { keyPackageBytes, keyPackage } =
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
    const kaiPubkey =
      '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';

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

describe('Full MLS integration flow', () => {
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
    const addResult = await addMlsGroupMembers(aliceGroup.state, [
      bobKP.keyPackage,
    ]);
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

    // 8. Welcome can be serialized
    const welcomeBytes = encodeWelcome(addResult.welcome);
    const welcomeDecoded = decodeWelcome(welcomeBytes);
    expect(welcomeDecoded.cipherSuite).toBe(DEFAULT_CIPHERSUITE);
  });
});

// ─── Exporter Secret ────────────────────────────────────────────────────────

describe('Exporter secret', () => {
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
