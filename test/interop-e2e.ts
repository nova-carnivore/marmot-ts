#!/usr/bin/env npx tsx
/**
 * End-to-End MLS Interop Test
 *
 * Fetches real KeyPackages from Nostr relays, parses them with both
 * the standalone varint parser and ts-mls, then tests a full MLS flow:
 * group creation → add member → verify Welcome → state serialization.
 *
 * Run: npx tsx test/interop-e2e.ts
 */

import WebSocket from 'ws';
import {
  parseKeyPackageRaw,
  parseKeyPackageBytes,
  generateMlsKeyPackage,
  createMlsGroup,
  addMlsGroupMembers,
  encodeMlsState,
  decodeMlsState,
  encodeWelcome,
  decodeWelcome,
  groupStateToClientState,
} from '../src/mls.js';

// ─── Config ─────────────────────────────────────────────────────────────────

const RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.primal.net',
  'wss://nos.lol',
];

// Known Marmot pubkeys
const KAI_PUBKEY = '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';
const NOVA_PUBKEY = '29e71f8eb89a571484d7b59874f224a5e2ae87af55aceaf33cd7d5443e200666';

// ─── Helpers ────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

/**
 * Fetch the latest kind:443 KeyPackage event for a pubkey from Nostr relays.
 */
async function fetchKeyPackageEvent(
  pubkey: string,
  relays: string[] = RELAYS,
  timeoutMs: number = 10000
): Promise<NostrEvent | null> {
  for (const relay of relays) {
    try {
      const event = await fetchFromRelay(relay, pubkey, timeoutMs);
      if (event) return event;
    } catch (e: any) {
      console.log(`  ⚠ ${relay}: ${e.message}`);
    }
  }
  return null;
}

function fetchFromRelay(
  relay: string,
  pubkey: string,
  timeoutMs: number
): Promise<NostrEvent | null> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(relay);
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error('timeout'));
    }, timeoutMs);

    ws.on('error', (e: Error) => {
      clearTimeout(timer);
      ws.close();
      reject(e);
    });

    ws.on('open', () => {
      ws.send(
        JSON.stringify([
          'REQ',
          'kp',
          { kinds: [443], authors: [pubkey], limit: 1 },
        ])
      );
    });

    let result: NostrEvent | null = null;
    ws.on('message', (data: WebSocket.Data) => {
      const msg = JSON.parse(data.toString());
      if (msg[0] === 'EVENT' && msg[2]) {
        result = msg[2] as NostrEvent;
      } else if (msg[0] === 'EOSE') {
        clearTimeout(timer);
        ws.close();
        resolve(result);
      }
    });
  });
}

/**
 * Decode event content to bytes (handles base64 and hex).
 */
function decodeEventContent(event: NostrEvent): Uint8Array {
  const encodingTag = event.tags.find((t) => t[0] === 'encoding');
  const encoding = encodingTag?.[1] || 'base64';

  if (encoding === 'hex' || /^[0-9a-f]+$/i.test(event.content)) {
    const hex = event.content;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  return Buffer.from(event.content, 'base64');
}

// ─── Test Steps ─────────────────────────────────────────────────────────────

interface TestResult {
  name: string;
  passed: boolean;
  detail?: string;
  error?: string;
}

const results: TestResult[] = [];

function pass(name: string, detail?: string) {
  results.push({ name, passed: true, detail });
  console.log(`  ✅ ${name}${detail ? ` — ${detail}` : ''}`);
}

function fail(name: string, error: string) {
  results.push({ name, passed: false, error });
  console.log(`  ❌ ${name} — ${error}`);
}

async function main() {
  console.log('═══════════════════════════════════════════════════');
  console.log(' MLS Interop End-to-End Test');
  console.log('═══════════════════════════════════════════════════');
  console.log();

  // ─── Step 1: Fetch Kai's KeyPackage from relay ────────────────────────
  console.log('Step 1: Fetch KeyPackage from Nostr relay');
  console.log(`  Target: Kai (${KAI_PUBKEY.substring(0, 12)}...)`);

  const kaiEvent = await fetchKeyPackageEvent(KAI_PUBKEY);
  if (!kaiEvent) {
    fail('Fetch KeyPackage', 'No KeyPackage found for Kai on any relay');
    printSummary();
    process.exit(1);
  }

  const clientTag = kaiEvent.tags.find((t) => t[0] === 'client');
  pass(
    'Fetch KeyPackage',
    `event ${kaiEvent.id.substring(0, 12)}... client=${clientTag?.[1] || 'unknown'} created_at=${new Date(kaiEvent.created_at * 1000).toISOString()}`
  );

  const kaiKpBytes = decodeEventContent(kaiEvent);
  pass('Decode content', `${kaiKpBytes.length} bytes`);

  // ─── Step 2: Parse with standalone varint parser ──────────────────────
  console.log();
  console.log('Step 2: Parse with parseKeyPackageRaw (varint parser)');

  try {
    const raw = parseKeyPackageRaw(kaiKpBytes);
    pass(
      'parseKeyPackageRaw',
      `version=${raw.version} suite=${raw.cipherSuite} identity=${raw.identityHex.substring(0, 12)}...`
    );

    // Verify identity matches event pubkey
    if (raw.identityHex === kaiEvent.pubkey) {
      pass('Identity matches event pubkey');
    } else {
      fail(
        'Identity matches event pubkey',
        `expected ${kaiEvent.pubkey.substring(0, 12)}..., got ${raw.identityHex.substring(0, 12)}...`
      );
    }

    // Show capabilities
    const greaseCount = raw.capabilities.ciphersuites.filter(
      (c) => (c & 0x0f0f) === 0x0a0a
    ).length;
    pass(
      'Capabilities parsed',
      `versions=[${raw.capabilities.versions.map((v) => '0x' + v.toString(16)).join(',')}] ` +
        `suites=[${raw.capabilities.ciphersuites.map((s) => '0x' + s.toString(16)).join(',')}] ` +
        `exts=[${raw.capabilities.extensions.map((e) => '0x' + e.toString(16)).join(',')}] ` +
        `GREASE values: ${greaseCount}`
    );

    // Verify kp_extensions contain last_resort
    const hasLastResort = raw.kpExtensions.some((e) => e.type === 0x000a);
    if (hasLastResort) {
      pass('kp_extensions contains last_resort (0x000a)');
    } else {
      fail('kp_extensions contains last_resort', 'missing 0x000a');
    }

    // Lifetime
    if (raw.notBefore !== undefined && raw.notAfter !== undefined) {
      const notBeforeDate = new Date(Number(raw.notBefore) * 1000);
      const notAfterDate = new Date(Number(raw.notAfter) * 1000);
      pass(
        'Lifetime parsed',
        `${notBeforeDate.toISOString()} → ${notAfterDate.toISOString()}`
      );
    }
  } catch (e: any) {
    fail('parseKeyPackageRaw', e.message);
  }

  // ─── Step 3: Parse with ts-mls parser ─────────────────────────────────
  console.log();
  console.log('Step 3: Parse with parseKeyPackageBytes (ts-mls)');

  let tsmlsParsed: ReturnType<typeof parseKeyPackageBytes> | null = null;
  try {
    tsmlsParsed = parseKeyPackageBytes(kaiKpBytes);
    pass(
      'parseKeyPackageBytes',
      `version=${tsmlsParsed.version} suite=${tsmlsParsed.cipherSuite}`
    );

    const tsmlsIdentity = bytesToHex(tsmlsParsed.leafNode.credential.identity);
    if (tsmlsIdentity === kaiEvent.pubkey) {
      pass('ts-mls identity matches', tsmlsIdentity.substring(0, 12) + '...');
    } else {
      fail(
        'ts-mls identity matches',
        `expected ${kaiEvent.pubkey.substring(0, 12)}..., got ${tsmlsIdentity.substring(0, 12)}...`
      );
    }
  } catch (e: any) {
    fail('parseKeyPackageBytes', e.message);
    console.log(
      '  ℹ ts-mls may not parse OpenMLS-generated KeyPackages — this is expected'
    );
  }

  // ─── Step 4: Generate local KeyPackage ────────────────────────────────
  console.log();
  console.log('Step 4: Generate local KeyPackage (Nova)');

  let novaKp: Awaited<ReturnType<typeof generateMlsKeyPackage>>;
  try {
    novaKp = await generateMlsKeyPackage(NOVA_PUBKEY);
    pass(
      'generateMlsKeyPackage',
      `${novaKp.keyPackageBytes.length} bytes`
    );

    // Verify it round-trips through our parser
    const novaRaw = parseKeyPackageRaw(novaKp.keyPackageBytes);
    if (novaRaw.identityHex === NOVA_PUBKEY) {
      pass('Nova KeyPackage round-trip identity matches');
    } else {
      fail(
        'Nova KeyPackage round-trip',
        `identity mismatch: ${novaRaw.identityHex}`
      );
    }
  } catch (e: any) {
    fail('generateMlsKeyPackage', e.message);
    printSummary();
    process.exit(1);
  }

  // ─── Step 5: Create MLS group ─────────────────────────────────────────
  console.log();
  console.log('Step 5: Create MLS group');

  let groupResult: Awaited<ReturnType<typeof createMlsGroup>>;
  try {
    const groupId = new Uint8Array(32);
    crypto.getRandomValues(groupId);
    groupResult = await createMlsGroup(groupId, NOVA_PUBKEY);
    pass(
      'createMlsGroup',
      `groupId=${bytesToHex(groupId).substring(0, 16)}... epoch=${groupResult.state.groupContext.epoch} exporterSecret=${bytesToHex(groupResult.exporterSecret).substring(0, 16)}...`
    );
  } catch (e: any) {
    fail('createMlsGroup', e.message);
    printSummary();
    process.exit(1);
  }

  // ─── Step 6: Add fetched member ───────────────────────────────────────
  console.log();
  console.log('Step 6: Add fetched member to group');

  if (tsmlsParsed) {
    try {
      const addResult = await addMlsGroupMembers(groupResult!.state, [
        tsmlsParsed,
      ]);
      pass(
        'addMlsGroupMembers',
        `epoch=${addResult.newState.groupContext.epoch}`
      );

      // ─── Step 6a: Verify Welcome ──────────────────────────────────────
      if (addResult.welcome) {
        pass(
          'Welcome message generated',
          `secrets=${addResult.welcome.secrets.length} suite=${addResult.welcome.cipherSuite}`
        );

        // Encode/decode Welcome round-trip
        try {
          const welcomeBytes = encodeWelcome(addResult.welcome);
          const welcomeDecoded = decodeWelcome(welcomeBytes);
          if (
            welcomeDecoded.cipherSuite === addResult.welcome.cipherSuite &&
            welcomeDecoded.secrets.length === addResult.welcome.secrets.length
          ) {
            pass(
              'Welcome encode/decode round-trip',
              `${welcomeBytes.length} bytes`
            );
          } else {
            fail('Welcome round-trip', 'mismatch after decode');
          }
        } catch (e: any) {
          fail('Welcome round-trip', e.message);
        }
      } else {
        fail('Welcome message', 'no Welcome generated');
      }

      // ─── Step 7: State serialization round-trip ───────────────────────
      console.log();
      console.log('Step 7: State serialization round-trip');

      try {
        const encoded = encodeMlsState(addResult.newState);
        const decoded = decodeMlsState(encoded);
        const clientState = groupStateToClientState(decoded);

        if (
          decoded.groupContext.epoch === addResult.newState.groupContext.epoch &&
          bytesToHex(decoded.groupContext.groupId) ===
            bytesToHex(addResult.newState.groupContext.groupId)
        ) {
          pass(
            'State serialization round-trip',
            `${encoded.length} bytes, epoch=${decoded.groupContext.epoch}`
          );
        } else {
          fail('State serialization round-trip', 'mismatch after decode');
        }

        if (clientState.clientConfig) {
          pass('groupStateToClientState', 'clientConfig attached');
        } else {
          fail('groupStateToClientState', 'missing clientConfig');
        }
      } catch (e: any) {
        fail('State serialization', e.message);
      }
    } catch (e: any) {
      fail('addMlsGroupMembers', e.message);
      console.log(
        '  ℹ This may fail if the fetched KeyPackage uses incompatible capabilities'
      );

      // Still test state serialization on the original group
      console.log();
      console.log('Step 7: State serialization round-trip (original group)');
      try {
        const encoded = encodeMlsState(groupResult!.state);
        const decoded = decodeMlsState(encoded);
        pass(
          'State serialization round-trip',
          `${encoded.length} bytes, epoch=${decoded.groupContext.epoch}`
        );
      } catch (e: any) {
        fail('State serialization', e.message);
      }
    }
  } else {
    console.log(
      '  ⚠ Skipping add member — ts-mls could not parse the fetched KeyPackage'
    );
    console.log(
      '  ℹ This is expected for OpenMLS-generated packages with different capability encoding'
    );

    // Test with a locally-generated KeyPackage instead
    console.log();
    console.log('Step 6 (fallback): Add locally-generated member');
    try {
      const bobPubkey =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      const bobKp = await generateMlsKeyPackage(bobPubkey);
      const addResult = await addMlsGroupMembers(groupResult!.state, [
        bobKp.keyPackage,
      ]);
      pass(
        'addMlsGroupMembers (local)',
        `epoch=${addResult.newState.groupContext.epoch}`
      );

      if (addResult.welcome) {
        pass(
          'Welcome message generated',
          `secrets=${addResult.welcome.secrets.length}`
        );
      }

      // State serialization
      console.log();
      console.log('Step 7: State serialization round-trip');
      const encoded = encodeMlsState(addResult.newState);
      const decoded = decodeMlsState(encoded);
      pass(
        'State serialization round-trip',
        `${encoded.length} bytes, epoch=${decoded.groupContext.epoch}`
      );
    } catch (e: any) {
      fail('Local member flow', e.message);
    }
  }

  // ─── Summary ──────────────────────────────────────────────────────────
  printSummary();
}

function printSummary() {
  console.log();
  console.log('═══════════════════════════════════════════════════');
  console.log(' Summary');
  console.log('═══════════════════════════════════════════════════');

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  for (const r of results) {
    if (r.passed) {
      console.log(`  ✅ ${r.name}`);
    } else {
      console.log(`  ❌ ${r.name}: ${r.error}`);
    }
  }

  console.log();
  console.log(
    `  ${passed} passed, ${failed} failed, ${results.length} total`
  );
  console.log();

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('Fatal error:', e);
  process.exit(1);
});
