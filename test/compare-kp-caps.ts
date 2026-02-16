import { SimplePool } from 'nostr-tools/pool';
import { parseKeyPackageBytes } from '../src/mls.js';

const TARGET = '4ec080ebf58822be2a23d902f252077f66f5da8e0ad90dd480f3959d3cd4da6f';
const KAI = '7bd07e03041573478d3f0e546f161b04c80fd85f9b2d29248d4f2b65147a4c3e';

async function main() {
  const pool = new SimplePool();
  const relays = ['wss://nos.lol', 'wss://relay.primal.net'];
  
  for (const [name, pubkey] of [['marmot-web', TARGET], ['Kai-MDK', KAI]] as const) {
    const events = await pool.querySync(relays, { kinds: [443], authors: [pubkey], limit: 1 });
    if (!events.length) { console.log(name, ': no KP'); continue; }
    const raw = Uint8Array.from(atob(events[0].content), c => c.charCodeAt(0));
    console.log('\n===', name, '=== (' + raw.length + ' bytes)');
    
    try {
      const kp = parseKeyPackageBytes(raw);
      // Dump everything
      const replacer = (k: string, v: any) => {
        if (v instanceof Uint8Array) return `Uint8Array(${v.length})[${Array.from(v.slice(0,8)).map(b => b.toString(16).padStart(2,'0')).join('')}...]`;
        if (typeof v === 'bigint') return v.toString();
        return v;
      };
      console.log('KP:', JSON.stringify(kp, replacer, 2).slice(0, 2000));
    } catch (e: any) {
      console.log('Parse error:', e.message);
    }
  }
  
  pool.close(relays);
}
main();
