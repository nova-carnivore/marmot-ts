/**
 * MLS Interop Example
 *
 * Demonstrates the full MLS lifecycle using marmot-ts:
 * 1. Generate KeyPackages for two users
 * 2. Create a group
 * 3. Add a member
 * 4. Member joins from Welcome
 * 5. Verify exporter secrets match
 * 6. Show ciphersuite info
 *
 * Run: npx tsx examples/mls-interop.ts
 */

import {
  DEFAULT_CIPHERSUITE,
  getSupportedCiphersuites,
  ciphersuiteNameToId,
  ciphersuiteIdToName,
  generateMlsKeyPackage,
  parseKeyPackageBytes,
  createMlsGroup,
  addMlsGroupMembers,
  joinMlsGroupFromWelcome,
  encodeWelcome,
  decodeWelcome,
  encodeMlsState,
  encodeKeyPackage,
} from '../src/mls.js';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function main() {
  console.log('=== Marmot MLS Interop Example ===\n');

  // ─── 1. Ciphersuite Info ──────────────────────────────────────────────
  console.log('📋 Ciphersuite Info:');
  console.log(`  Default: ${DEFAULT_CIPHERSUITE}`);
  console.log(`  ID: 0x${ciphersuiteNameToId(DEFAULT_CIPHERSUITE).toString(16).padStart(4, '0')}`);
  const allSuites = getSupportedCiphersuites();
  console.log(`  Total supported: ${allSuites.length}`);
  console.log(
    `  All suites: ${allSuites.map((s) => `${s} (0x${ciphersuiteNameToId(s).toString(16).padStart(4, '0')})`).join(', ')}\n`
  );

  // ─── 2. Generate KeyPackages ──────────────────────────────────────────
  const alicePubkey =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const bobPubkey =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  console.log('🔑 Generating KeyPackages...');
  const aliceKP = await generateMlsKeyPackage(alicePubkey);
  const bobKP = await generateMlsKeyPackage(bobPubkey);

  console.log(`  Alice KP: ${aliceKP.keyPackageBytes.length} bytes (raw TLS format)`);
  console.log(`  Bob KP: ${bobKP.keyPackageBytes.length} bytes (raw TLS format)`);
  console.log(
    `  Alice identity: ${bytesToHex(aliceKP.keyPackage.leafNode.credential.identity)}`
  );
  console.log(
    `  Bob identity: ${bytesToHex(bobKP.keyPackage.leafNode.credential.identity)}\n`
  );

  // ─── 3. Parse KeyPackage (round-trip) ──────────────────────────────────
  console.log('🔍 Parsing KeyPackage (round-trip)...');
  const parsedKP = parseKeyPackageBytes(aliceKP.keyPackageBytes);
  console.log(`  Version: ${parsedKP.version}`);
  console.log(`  Ciphersuite: ${parsedKP.cipherSuite}`);
  console.log(
    `  Identity: ${bytesToHex(parsedKP.leafNode.credential.identity)}\n`
  );

  // ─── 4. Create Group ──────────────────────────────────────────────────
  console.log('🏠 Creating group...');
  const groupId = new Uint8Array(32);
  crypto.getRandomValues(groupId);

  const aliceGroup = await createMlsGroup(groupId, alicePubkey);
  console.log(`  Group ID: ${bytesToHex(aliceGroup.groupId)}`);
  console.log(`  Epoch: ${aliceGroup.state.groupContext.epoch}`);
  console.log(`  Exporter secret: ${bytesToHex(aliceGroup.exporterSecret)}`);
  console.log(`  State size: ${aliceGroup.encodedState.length} bytes\n`);

  // ─── 5. Add Bob to Group ──────────────────────────────────────────────
  console.log('➕ Adding Bob to group...');
  const addResult = await addMlsGroupMembers(aliceGroup.state, [
    bobKP.keyPackage,
  ]);
  console.log(`  New epoch: ${addResult.newState.groupContext.epoch}`);
  console.log(`  Welcome generated: ✅`);
  console.log(`  Alice exporter: ${bytesToHex(addResult.exporterSecret)}`);

  // Serialize Welcome (this is what would be sent to Bob via Nostr)
  const welcomeBytes = encodeWelcome(addResult.welcome);
  console.log(`  Welcome size: ${welcomeBytes.length} bytes\n`);

  // ─── 6. Bob Joins from Welcome ────────────────────────────────────────
  console.log('📨 Bob joining from Welcome...');
  // In a real scenario, Bob would receive the Welcome via a kind:444 event
  const welcomeDecoded = decodeWelcome(welcomeBytes);

  const bobGroup = await joinMlsGroupFromWelcome(
    welcomeDecoded,
    bobKP.keyPackage,
    bobKP.privateKeyPackage
  );
  console.log(`  Bob epoch: ${bobGroup.state.groupContext.epoch}`);
  console.log(`  Bob group ID: ${bytesToHex(bobGroup.groupId)}`);
  console.log(`  Bob exporter: ${bytesToHex(bobGroup.exporterSecret)}\n`);

  // ─── 7. Verify Secrets Match ──────────────────────────────────────────
  const secretsMatch =
    bytesToHex(addResult.exporterSecret) ===
    bytesToHex(bobGroup.exporterSecret);
  console.log(
    `🔐 Exporter secrets match: ${secretsMatch ? '✅ YES' : '❌ NO'}`
  );

  const groupIdMatch =
    bytesToHex(aliceGroup.groupId) === bytesToHex(bobGroup.groupId);
  console.log(
    `🆔 Group IDs match: ${groupIdMatch ? '✅ YES' : '❌ NO'}\n`
  );

  // ─── 8. State Persistence ──────────────────────────────────────────────
  console.log('💾 State persistence:');
  const aliceStateBytes = encodeMlsState(addResult.newState);
  const bobStateBytes = encodeMlsState(bobGroup.state);
  console.log(`  Alice state: ${aliceStateBytes.length} bytes`);
  console.log(`  Bob state: ${bobStateBytes.length} bytes\n`);

  // ─── 9. KeyPackage Wire Format ─────────────────────────────────────────
  console.log('📦 KeyPackage wire format:');
  const rawKP = encodeKeyPackage(aliceKP.keyPackage);
  console.log(
    `  Raw format: ${rawKP.length} bytes, starts with 0x${bytesToHex(rawKP.slice(0, 4))}`
  );
  console.log(
    `  (version=0x0001, ciphersuite=0x${ciphersuiteNameToId(DEFAULT_CIPHERSUITE).toString(16).padStart(4, '0')})\n`
  );

  console.log('=== Done! ===');
}

main().catch(console.error);
