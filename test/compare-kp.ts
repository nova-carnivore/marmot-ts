import { SimplePool } from 'nostr-tools/pool';

const pool = new SimplePool();
const relays = ['wss://nos.lol'];
const TARGET = '4ec0807afd4411578a8a3d90bc9480fed9bd768e0ab640dd403ce5674d14da6e';
const KAI = '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';

async function main() {
  const [targetKPs, kaiKPs] = await Promise.all([
    pool.querySync(relays, { kinds: [443], authors: [TARGET], limit: 1 }),
    pool.querySync(relays, { kinds: [443], authors: [KAI], limit: 1 })
  ]);

  for (const [name, events] of [['marmot-web', targetKPs], ['Kai-MDK', kaiKPs]]) {
    if (!events.length) { console.log(name, ': no KP'); continue; }
    const ev = events[0];
    const raw = Uint8Array.from(atob(ev.content), c => c.charCodeAt(0));
    console.log('\n===', name, '===');
    console.log('Size:', raw.length, 'bytes');
    console.log('Tags:', ev.tags.filter(t => t[0].startsWith('mls_')).map(t => t.join('=')).join(', '));
    console.log('Client:', ev.tags.find(t => t[0] === 'client')?.[1] || 'none');
    console.log('Hex (first 120):', Buffer.from(raw.slice(0,120)).toString('hex'));
  }

  pool.close(relays);
}
main();
