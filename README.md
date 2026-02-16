# marmot-ts

[![CI](https://github.com/nova-carnivore/marmot-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/nova-carnivore/marmot-ts/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/marmot-ts.svg)](https://www.npmjs.com/package/marmot-ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org/)

TypeScript library for the **[Marmot Protocol](https://github.com/marmot-protocol/marmot)** — secure, decentralized group messaging combining [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html) with [Nostr](https://github.com/nostr-protocol/nostr).

## Features

- 🔐 **Full MIP implementation** — MIP-00 through MIP-04
- 📦 **Modular** — import only what you need (`marmot-ts/mip00`, etc.)
- 🔑 **Signer abstraction** — NIP-07, NIP-46, and private key signers
- 🛡️ **Security-first** — credential validation, unsigned inner events, ephemeral keypairs
- 🧪 **254 tests** — comprehensive coverage across all MIPs + MLS runtime
- 🌍 **Cross-platform** — Node.js 20+, Bun, Deno, browsers

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

The Marmot protocol flow:
1. **marmot-ts/mls** generates MLS KeyPackages, Welcomes, Commits via ts-mls
2. **marmot-ts** wraps them in Nostr events with proper encoding, encryption, and metadata
3. **nostr-tools** publishes/subscribes to relay events

## Architecture

```
marmot-ts/
├── src/
│   ├── index.ts      # Main exports
│   ├── types.ts      # All type definitions
│   ├── utils.ts      # Encoding, validation, helpers
│   ├── crypto.ts     # SHA-256, HKDF, ChaCha20-Poly1305, secp256k1
│   ├── signer.ts     # MarmotSigner interface + implementations
│   ├── mls.ts        # MLS runtime operations (ts-mls wrapper)
│   ├── mip00.ts      # Credentials & Key Packages (kind: 443)
│   ├── mip01.ts      # Group Construction & Marmot Group Data (0xF2EE)
│   ├── mip02.ts      # Welcome Events (kind: 444) + NIP-59
│   ├── mip03.ts      # Group Messages (kind: 445) + ephemeral keys
│   └── mip04.ts      # Encrypted Media + Blossom storage
├── examples/
│   └── mls-interop.ts # MLS lifecycle example
└── test/             # 254 tests across all modules
```

## Related Projects

- [Marmot Protocol Spec](https://github.com/marmot-protocol/marmot) — Protocol specification
- [MDK](https://github.com/marmot-protocol/mdk) — Rust implementation
- [ts-mls](https://github.com/LukaJCB/ts-mls) — Pure TypeScript MLS (RFC 9420)
- [nostr-tools](https://github.com/nbd-wtf/nostr-tools) — Nostr client library

## License

[MIT](./LICENSE)
