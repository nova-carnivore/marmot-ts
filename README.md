# marmot-ts

[![CI](https://github.com/nova-carnivore/marmot-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/nova-carnivore/marmot-ts/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/marmot-ts.svg)](https://www.npmjs.com/package/marmot-ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org/)

TypeScript library for the **[Marmot Protocol](https://github.com/marmot-protocol/marmot)** — secure, decentralized group messaging combining [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr](https://github.com/nostr-protocol/nostr).

> **⚠️ Status: Work In Progress — Not Production Ready**
>
> This library implements all MIP specifications and has 300+ passing tests, but **MLS interoperability with [MDK](https://github.com/marmot-protocol/mdk) (the Rust reference implementation) is incomplete.**
>
> **What works:**
> - ✅ MDK → marmot-ts: Receiving Welcome events from MDK, joining MLS groups, decrypting group data (v2 wire format)
> - ✅ Nostr event creation/parsing for all MIP kinds (443, 444, 445)
> - ✅ NIP-59 gift wrapping for Welcome events
> - ✅ MLS KeyPackage generation, group creation, Welcome/Commit production (via ts-mls)
> - ✅ All crypto: Ed25519, X25519, HKDF, ChaCha20-Poly1305
> - ✅ **marmot-web ↔ marmot-web:** Fully working bidirectional chat (verified 2026-02-16)
> - ✅ Node.js 20+, Bun, Deno — all CI green
>
> **What doesn't work:**
> - ❌ marmot-ts → MDK: Welcome messages produced by ts-mls are rejected by MDK ("invalid welcome message")
> - ❌ MDK rejects marmot-ts KeyPackages when creating new groups: `"The capabilities of the add proposal are insufficient for this group"` — despite capabilities being set correctly in source code
>
> **Root cause (best understanding):**
> The underlying MLS library ([ts-mls](https://github.com/LukaJCB/ts-mls)) has encoding incompatibilities with [OpenMLS](https://github.com/openmls/openmls) (used by MDK). Specifically:
> - In **browser contexts**, ts-mls drops the `0xf2ee` (marmot_group_data) extension from KeyPackage capabilities during encoding, even though the source code correctly specifies it. KeyPackages generated in Node.js include it correctly. This appears to be a ts-mls browser serialization bug.
> - The MLS Welcome binary encoding produced by ts-mls is not accepted by OpenMLS, even when capabilities match.
>
> **Implication:** This library can receive and process messages from MDK/marmot-cli users, but cannot initiate new groups that MDK users can join. Bidirectional messaging requires the group to be created by the MDK side.

## Features

- 🔐 **Full MIP implementation** — MIP-00 through MIP-04
- ✅ **MLS RFC 9420 encryption** — via ts-mls
- ✅ **NIP-59 gift-wrapped Welcomes** — full privacy with ephemeral keypairs
- ✅ **0xf2ee extension support** (Marmot Group Data) — **FIXED 2026-02-16**
- ✅ **KeyPackage creation** with required extensions (0xf2ee, 0x000a)
- ✅ **Group creation + member management** — add members, Welcome flow
- ✅ **Bidirectional messaging** — marmot-web ↔ marmot-web verified
- ✅ **Follow list management** (kind:3) — create, parse, modify follow events
- ✅ **KeyPackage lifecycle** — validation, extension checking, availability tracking
- 📦 **Modular** — import only what you need (`marmot-ts/mip00`, `marmot-ts/social`, etc.)
- 🔑 **Signer abstraction** — NIP-07, NIP-46, and private key signers
- 🛡️ **Security-first** — credential validation, unsigned inner events, ephemeral keypairs
- 🧪 **300 tests** — comprehensive coverage across all MIPs + MLS runtime
- 🌍 **Cross-platform** — Node.js 20+, Bun, Deno, browsers

## Known Issues

- ⚠️ **Timestamp workaround:** NIP-59 timestamp randomization reduced to 2-120 minutes (was 0-48 hours) to work around marmot-cli fetching issue
- ⚠️ **marmot-cli interop:** Welcome events published by marmot-web are NOT retrieved by marmot-cli (see [kai-familiar/marmot-cli#8](https://github.com/kai-familiar/marmot-cli/issues/8))
- ℹ️ **marmot-web ↔ marmot-web:** Fully working (bidirectional chat verified)

## Recent Fixes (2026-02-16)

- **0xf2ee Extension Bug:** `createMlsGroup()` was called with empty extensions array, preventing Welcome recipients from extracting group metadata. Fixed by adding `GroupContextExtension` with serialized Marmot Group Data.
- **Welcome subscription window:** Widened from 24h to 48h to match NIP-59 timestamp randomization range.
- **Timestamp randomization:** Reduced to 2-120 minutes as pragmatic workaround for relay compatibility.
- **New modules:** Added `social.ts`, `keypackage-manager.ts`, `group-management.ts`, and `welcome.ts` with reusable helpers extracted from marmot-web.

## Install

```bash
npm install marmot-ts
```

## Quick Start

```typescript
import {
  createKeyPackageEvent,
  createGroupData,
  serializeMarmotGroupData,
  createWelcomeRumor,
  createGroupEvent,
  createApplicationMessage,
  encryptMedia,
  PrivateKeySigner,
  generateKeypair,
  MLS_CIPHERSUITES,
} from 'marmot-ts';

// Generate a test keypair
const keypair = generateKeypair();
const signer = new PrivateKeySigner(keypair.privateKeyHex);
```

## Usage Examples

### Follow List Management

```typescript
import {
  publishFollowList,
  parseFollowList,
  addToFollowList,
} from 'marmot-ts/social';

// Publish a follow list
const currentFollows = ['pubkey1...', 'pubkey2...'];
const newFollows = addToFollowList(currentFollows, 'newPubkey...');
const event = await publishFollowList(signer, newFollows);
await pool.publish(relays, event);

// Parse a follow list from a kind:3 event
const follows = parseFollowList(receivedEvent);
```

### KeyPackage Management

```typescript
import { KeyPackageManager } from 'marmot-ts/keypackage-manager';

const kpManager = new KeyPackageManager();

// Validate a KeyPackage event
const result = kpManager.validateKeyPackageEvent(keyPackageEvent);
console.log(result.hasRequiredExtensions); // true/false
console.log(result.errors); // any validation errors

// Filter to only valid KeyPackages
const valid = kpManager.filterValid(keyPackageEvents);

// Select the best KeyPackage for a pubkey
const best = kpManager.selectBest(keyPackageEvents, contactPubkey);

// Check availability for multiple contacts
const availability = kpManager.checkAvailability(events, contactPubkeys);
// Map<string, boolean>
```

### Group Member Management

```typescript
import { addGroupMembers } from 'marmot-ts/group-management';
import { wrapWelcomes } from 'marmot-ts/welcome';

// Add members (after fetching their KeyPackages from relays)
const result = await addGroupMembers(fetchedKeyPackages, {
  mlsState: currentState,
  relays: ['wss://relay.example.com'],
  senderPubkey: myPubkey,
});

// Gift-wrap and send the Welcome events
const wrapped = await wrapWelcomes(signer, result.welcomeRumors.map(r => ({
  recipientPubkey: r.recipientPubkey,
  welcomeRumor: r.rumor,
})));

for (const w of wrapped) {
  if (w.success) await pool.publish(relays, w.giftWrap);
}
```

### Complete Welcome Flow

```typescript
import { createAndWrapWelcomes } from 'marmot-ts/welcome';

// Highest-level helper: create + gift-wrap Welcomes in one call
const results = await createAndWrapWelcomes(signer, {
  senderPubkey: myPubkey,
  welcomeBytes: encodedWelcome,
  relays: ['wss://relay.example.com'],
  recipients: [
    { pubkey: 'member1...', keyPackageEventId: 'kp-event-1' },
    { pubkey: 'member2...', keyPackageEventId: 'kp-event-2' },
  ],
});

for (const r of results) {
  if (r.success) await pool.publish(relays, r.giftWrap);
}
```

## MIP Implementations

### MIP-00: Credentials & Key Packages

KeyPackage events (`kind: 443`) enable asynchronous group invitations.

```typescript
import {
  createKeyPackageEvent,
  parseKeyPackageEvent,
  validateCredentialIdentity,
  pubkeyToCredentialIdentity,
  createKeyPackageDeletionEvent,
  MLS_CIPHERSUITES,
} from 'marmot-ts/mip00';

// Create a KeyPackage event
const event = createKeyPackageEvent(pubkey, {
  keyPackageData: mlsKeyPackageBytes,
  ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
  relays: ['wss://relay.example.com'],
  clientName: 'my-app',
});

// Parse a received KeyPackage
const parsed = parseKeyPackageEvent(receivedEvent);

// Validate MLS credential identity matches Nostr pubkey
const identity = pubkeyToCredentialIdentity(nostrPubkey);
const valid = validateCredentialIdentity(identity, nostrPubkey); // true

// Delete consumed KeyPackage
const deletion = createKeyPackageDeletionEvent(pubkey, [eventId]);
```

### MIP-01: Group Construction

Create groups with the Marmot Group Data Extension (`0xF2EE`).

```typescript
import {
  createGroupData,
  serializeMarmotGroupData,
  deserializeMarmotGroupData,
  isAdmin,
  verifyAdminAuthorization,
  encryptGroupImage,
  decryptGroupImage,
} from 'marmot-ts/mip01';

// Create a new group
const groupData = createGroupData({
  name: 'Secret Marmot Club 🦫',
  description: 'End-to-end encrypted group chat',
  adminPubkeys: [myPubkey],
  relays: ['wss://relay.example.com'],
});

// TLS-serialize for MLS extension
const bytes = serializeMarmotGroupData(groupData);
const restored = deserializeMarmotGroupData(bytes);

// Admin checks
isAdmin(groupData, myPubkey);                            // true
verifyAdminAuthorization(groupData, memberPubkey, true); // self-update OK

// Group image encryption (ChaCha20-Poly1305)
const { encryptedImage, imageHash, imageKey, imageNonce } =
  encryptGroupImage(imageData);
const decrypted = decryptGroupImage(encryptedImage, imageKey, imageNonce);
```

### MIP-02: Welcome Events

Secure group invitations via NIP-59 gift wrapping.

```typescript
import {
  createWelcomeRumor,
  parseWelcomeEvent,
  CommitWelcomeOrderTracker,
  validateWelcomeEvent,
} from 'marmot-ts/mip02';

// Create Welcome (MUST be unsigned)
const welcome = createWelcomeRumor(adminPubkey, {
  welcomeData: mlsWelcomeBytes,
  keyPackageEventId: 'kp-event-id',
  relays: ['wss://relay.example.com'],
});

// Commit/Welcome ordering (CRITICAL for state fork prevention)
const tracker = new CommitWelcomeOrderTracker();
const ready = tracker.queueWelcome('commit-id', recipientPubkey, welcome);
// ready === false → wait for commit confirmation
const released = tracker.confirmCommit('commit-id');
// released contains Welcome events safe to send
```

### MIP-03: Group Messages

Encrypted group events (`kind: 445`) with ephemeral keypairs.

```typescript
import {
  createGroupEvent,
  parseGroupEvent,
  createApplicationMessage,
  validateApplicationMessage,
  serializeApplicationMessage,
  selectWinningCommit,
} from 'marmot-ts/mip03';

// Create a group event (fresh ephemeral keypair each time)
const { event, ephemeralPrivateKey } = await createGroupEvent({
  encryptedContent: nip44EncryptedMlsMessage,
  nostrGroupId: groupIdHex,
});

// Create application message (MUST be unsigned)
const chatMsg = createApplicationMessage(myPubkey, 'Hello 🦫');
const json = serializeApplicationMessage(chatMsg);

// Resolve commit race conditions
const winner = selectWinningCommit([
  { createdAt: 1000, eventId: 'aaa' },
  { createdAt: 1000, eventId: 'bbb' },
]);
// winner.eventId === 'aaa' (lexicographically smaller)
```

### MIP-04: Encrypted Media

Encrypt files with ChaCha20-Poly1305 + MLS exporter secrets.

```typescript
import {
  encryptMedia,
  decryptMedia,
  buildImetaTag,
  parseImetaTag,
} from 'marmot-ts/mip04';

// Encrypt media (v2 with random nonce)
const result = encryptMedia({
  data: fileContent,
  mimeType: 'image/jpeg',
  filename: 'photo.jpg',
  exporterSecret: mlsExporterSecret,
});

// Upload result.encryptedData to Blossom, then set URL
result.meta.url = `https://blossom.example.com/${result.encryptedHash}`;

// Build imeta tag for the group message
const tag = buildImetaTag(result.meta);
// ["imeta", "url https://...", "m image/jpeg", "filename photo.jpg", ...]

// Decrypt received media
const original = decryptMedia({
  encryptedData: downloadedBlob,
  meta: parseImetaTag(imetaTag),
  exporterSecret: mlsExporterSecret,
});
```

## Signer Support

```typescript
import { PrivateKeySigner, Nip07Signer, Nip46Signer } from 'marmot-ts/signer';

// Private key (testing/backend)
const signer = new PrivateKeySigner(hexPrivateKey);

// NIP-07 browser extension (Alby, nos2x, etc.)
const browserSigner = new Nip07Signer();

// NIP-46 remote signer (bunker)
const remoteSigner = new Nip46Signer({
  remotePubkey: '...',
  relayUrl: 'wss://relay.example.com',
});
```

## Security Requirements

This library enforces critical security requirements from the Marmot spec:

| Requirement | Enforcement |
|---|---|
| **Credential validation** | `validateCredentialIdentity()` — MLS identity MUST match Nostr pubkey |
| **Commit/Welcome ordering** | `CommitWelcomeOrderTracker` — prevents state forks |
| **Ephemeral keypairs** | `createGroupEvent()` — fresh keypair per kind:445 event |
| **Unsigned inner events** | `createApplicationMessage()` / `validateApplicationMessage()` — prevents leak publication |
| **Admin authorization** | `verifyAdminAuthorization()` — checks admin_pubkeys for non-self-update commits |
| **TLS serialization** | `serializeMarmotGroupData()` — exact byte-level format |

### MLS Runtime Operations

The `marmot-ts/mls` module wraps [ts-mls](https://github.com/LukaJCB/ts-mls) to provide protocol-level MLS operations. This ensures all Marmot clients use compatible wire formats and ciphersuites.

```typescript
import {
  generateMlsKeyPackage,
  parseKeyPackageBytes,
  parseKeyPackageFromEvent,
  createMlsGroup,
  addMlsGroupMembers,
  joinMlsGroupFromWelcome,
  deriveExporterSecret,
  DEFAULT_CIPHERSUITE,
  encodeWelcome,
  decodeWelcome,
} from 'marmot-ts/mls';

// Generate a KeyPackage (raw TLS format, compatible with all Marmot clients)
const { keyPackageBytes, keyPackage, privateKeyPackage } =
  await generateMlsKeyPackage(nostrPubkeyHex);

// Parse a KeyPackage from relay data (handles both raw and MLSMessage-wrapped)
const parsed = parseKeyPackageBytes(keyPackageBytes);

// Parse directly from a kind:443 Nostr event
const { parsed: eventData, mlsKeyPackage } =
  parseKeyPackageFromEvent(receivedEvent);

// Create a group
const group = await createMlsGroup(groupIdBytes, myPubkeyHex);
console.log('Exporter secret:', group.exporterSecret);

// Add a member — produces Welcome + Commit
const { welcome, newState, exporterSecret } =
  await addMlsGroupMembers(group.state, [memberKeyPackage]);

// Member joins from Welcome — exporter secrets will match
const joined = await joinMlsGroupFromWelcome(
  welcome, memberKeyPackage, memberPrivateKeyPackage
);
// joined.exporterSecret === exporterSecret ✅
```

## MLS Integration

The library now provides **built-in MLS support** via the `marmot-ts/mls` module, wrapping [ts-mls](https://github.com/LukaJCB/ts-mls) for protocol-level MLS operations:

- **KeyPackage generation** — raw TLS format compatible with marmot-cli, MDK, and marmot-chat
- **KeyPackage parsing** — handles raw and MLSMessage-wrapped formats
- **Group creation** — with automatic exporter secret derivation
- **Member management** — Add proposals + Commit + Welcome generation
- **Welcome processing** — join groups with matching exporter secrets
- **State serialization** — encode/decode for persistence

### Wire Format (per MIP specs)

| Object | Wire Format | Details |
|--------|------------|---------|
| **KeyPackage** (MIP-00) | Raw TLS-serialized | `encodeKeyPackage()` — starts with `0x0001` (version) + ciphersuite |
| **Welcome** (MIP-02) | MLSMessage-wrapped | `encodeWelcome()` — starts with `0x0001 0x0003` (version + mls_welcome wireformat) |

`parseKeyPackageBytes()` primarily expects raw format, with MLSMessage detection as a fallback.
`decodeWelcome()` primarily expects MLSMessage-wrapped format, with raw fallback for compatibility.

The Marmot protocol flow:
1. **marmot-ts/mls** generates MLS KeyPackages, Welcomes, Commits via ts-mls
2. **marmot-ts** wraps them in Nostr events with proper encoding, encryption, and metadata
3. **nostr-tools** publishes/subscribes to relay events

## Architecture

```
marmot-ts/
├── src/
│   ├── index.ts               # Main exports
│   ├── types.ts               # All type definitions
│   ├── utils.ts               # Encoding, validation, helpers
│   ├── crypto.ts              # SHA-256, HKDF, ChaCha20-Poly1305, secp256k1
│   ├── signer.ts              # MarmotSigner interface + implementations
│   ├── mls.ts                 # MLS runtime operations (ts-mls wrapper)
│   ├── mip00.ts               # Credentials & Key Packages (kind: 443)
│   ├── mip01.ts               # Group Construction & Marmot Group Data (0xF2EE)
│   ├── mip02.ts               # Welcome Events (kind: 444) + NIP-59
│   ├── mip03.ts               # Group Messages (kind: 445) + ephemeral keys
│   ├── mip04.ts               # Encrypted Media + Blossom storage
│   ├── social.ts              # Follow list management (kind: 3)
│   ├── keypackage-manager.ts  # KeyPackage lifecycle & validation
│   ├── group-management.ts    # Group member add/leave helpers
│   └── welcome.ts             # Complete Welcome publishing flow
├── examples/
│   └── mls-interop.ts         # MLS lifecycle example
└── test/                      # 300 tests across all modules
```

## Related Projects

- [Marmot Protocol Spec](https://github.com/marmot-protocol/marmot) — Protocol specification
- [MDK](https://github.com/marmot-protocol/mdk) — Rust implementation
- [ts-mls](https://github.com/LukaJCB/ts-mls) — Pure TypeScript MLS (RFC 9420)
- [nostr-tools](https://github.com/nbd-wtf/nostr-tools) — Nostr client library
- [marmot-web](https://github.com/nova-carnivore/marmot-web) — Reference web client

## License

[MIT](./LICENSE)
