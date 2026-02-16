import { parseKeyPackageFromEvent, generateMlsKeyPackage, createMlsGroup, addMlsGroupMembers, encodeWelcome } from '../src/mls.js';
import { SimplePool } from 'nostr-tools/pool';

const KAI_PUBKEY = '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';
const NOVA_PUBKEY = '29e71f8eb89a571484d7b59874f224a5e2ae87af55aceaf33cd7d5443e200666';

async function main() {
  console.log('=== Marmot Interop: marmot-ts ↔ marmot-cli ===\n');

  const pool = new SimplePool();
  const relays = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'];

  // 1. Fetch Kai's KeyPackage
  console.log('1. Fetching Kai KeyPackage from relays...');
  const events = await pool.querySync(relays, { kinds: [443], authors: [KAI_PUBKEY], limit: 1 });
  if (!events.length) { console.log('❌ No KP found'); process.exit(1); }
  const kaiEvent = events[0];
  console.log(`   ✅ Event: ${kaiEvent.id.slice(0, 16)}...`);
  console.log(`   Client: ${kaiEvent.tags.find(t => t[0] === 'client')?.[1] || 'unknown'}`);
  console.log(`   Ciphersuite: ${kaiEvent.tags.find(t => t[0] === 'mls_ciphersuite')?.[1]}`);

  // 2. Parse with marmot-ts
  console.log('\n2. Parsing Kai KeyPackage...');
  const kaiResult = parseKeyPackageFromEvent(kaiEvent);
  const rawBytes = kaiResult.parsed.keyPackageData;
  console.log(`   ✅ Parsed: ${rawBytes.length} bytes, ciphersuite=${kaiResult.parsed.ciphersuite}`);
  console.log(`   Header: ${Array.from(rawBytes.slice(0, 4)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`);
  console.log(`   mlsKeyPackage type: ${typeof kaiResult.mlsKeyPackage}`);

  // 3. Generate Nova KeyPackage  
  console.log('\n3. Generating Nova KeyPackage...');
  const novaKP = await generateMlsKeyPackage(NOVA_PUBKEY);
  console.log(`   ✅ ${novaKP.keyPackageBytes.length} bytes`);

  // 4. Create group
  console.log('\n4. Creating MLS group...');
  const gidHex = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
  const group = await createMlsGroup(gidHex, NOVA_PUBKEY);
  console.log(`   ✅ Group created: ${gidHex}`);
  console.log(`   State keys: ${Object.keys(group.state).join(', ')}`);
  console.log(`   Exporter: ${Array.from(group.exporterSecret.slice(0,8)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);

  // 5. Add Kai
  console.log('\n5. Adding Kai to group...');
  const addResult = await addMlsGroupMembers(group.state, [kaiResult.mlsKeyPackage]);
  console.log(`   ✅ Added!`);
  console.log(`   newState keys: ${Object.keys(addResult.newState).join(', ')}`);
  console.log(`   Exporter: ${Array.from(addResult.exporterSecret.slice(0,8)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);
  
  // 6. Encode Welcome
  const welcomeBytes = encodeWelcome(addResult.welcome);
  console.log(`   Welcome: ${welcomeBytes.length} bytes (MLSMessage-wrapped per MIP-02)`);
  console.log(`   Header: ${Array.from(welcomeBytes.slice(0, 4)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`);

  console.log('\n🎉 FULL INTEROP PIPELINE WORKS');
  console.log('   marmot-ts can:');
  console.log('   ✅ Parse marmot-cli (MDK) KeyPackages from relay');
  console.log('   ✅ Create MLS group with matching ciphersuite 0x0001');
  console.log('   ✅ Add real marmot-cli member via their KeyPackage');
  console.log('   ✅ Generate Welcome message for the new member');

  pool.close(relays);
}

main().catch(e => { console.error('❌ FAILED:', e.message, '\n', e.stack?.split('\n').slice(0,5).join('\n')); process.exit(1); });
