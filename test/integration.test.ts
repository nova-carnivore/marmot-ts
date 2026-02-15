import { describe, it, expect } from 'vitest';
import {
  // Types
  MARMOT_EVENT_KINDS,
  MLS_CIPHERSUITES,
  MLS_EXTENSION_TYPES,
  MEDIA_VERSION,

  // Signer
  PrivateKeySigner,

  // Crypto
  generateKeypair,

  // MIP-00
  createKeyPackageEvent,
  parseKeyPackageEvent,
  validateCredentialIdentity,
  pubkeyToCredentialIdentity,
  hasRequiredMarmotExtensions,
  createKeyPackageDeletionEvent,

  // MIP-01
  createGroupData,
  serializeMarmotGroupData,
  deserializeMarmotGroupData,
  isAdmin,
  verifyAdminAuthorization,
  encryptGroupImage,
  decryptGroupImage,
  getNostrGroupIdHex,

  // MIP-02
  createWelcomeRumor,
  parseWelcomeEvent,
  CommitWelcomeOrderTracker,
  validateWelcomeEvent,

  // MIP-03
  createGroupEvent,
  parseGroupEvent,
  createApplicationMessage,
  validateApplicationMessage,
  verifyApplicationMessageSender,
  serializeApplicationMessage,
  deserializeApplicationMessage,
  selectWinningCommit,

  // MIP-04
  encryptMedia,
  decryptMedia,
  buildImetaTag,
  parseImetaTag,

  // Utils
  randomBytes,
} from '../src/index.js';

describe('Integration Tests', () => {
  describe('Full protocol flow', () => {
    it('should create group, prepare messages, and handle media', async () => {
      // ─── Step 1: Generate test keypairs ──────────────────────────
      const adminKeypair = generateKeypair();
      const memberKeypair = generateKeypair();
      const _adminSigner = new PrivateKeySigner(adminKeypair.privateKeyHex);

      // ─── Step 2: Create KeyPackage for member ────────────────────
      const memberKeyPackageData = randomBytes(128);
      const keyPackageEvent = createKeyPackageEvent(memberKeypair.publicKeyHex, {
        keyPackageData: memberKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.example.com'],
        clientName: 'marmot-ts-test',
      });

      expect(keyPackageEvent.kind).toBe(443);

      // Parse it back
      keyPackageEvent.id = 'test-kp-event-id';
      const parsedKP = parseKeyPackageEvent(keyPackageEvent);
      expect(parsedKP.pubkey).toBe(memberKeypair.publicKeyHex);
      expect(hasRequiredMarmotExtensions(parsedKP)).toBe(true);

      // Validate credential identity
      const identity = pubkeyToCredentialIdentity(memberKeypair.publicKeyHex);
      expect(validateCredentialIdentity(identity, memberKeypair.publicKeyHex)).toBe(true);

      // ─── Step 3: Create group ────────────────────────────────────
      const groupData = createGroupData({
        name: 'Integration Test Group',
        description: 'Testing the full flow',
        adminPubkeys: [adminKeypair.publicKeyHex],
        relays: ['wss://relay1.example.com'],
      });

      expect(groupData.version).toBe(1);
      expect(groupData.nostrGroupId.length).toBe(32);
      expect(isAdmin(groupData, adminKeypair.publicKeyHex)).toBe(true);
      expect(isAdmin(groupData, memberKeypair.publicKeyHex)).toBe(false);

      // Admin can commit
      expect(verifyAdminAuthorization(groupData, adminKeypair.publicKeyHex, false)).toBe(
        true
      );
      // Non-admin can only self-update
      expect(verifyAdminAuthorization(groupData, memberKeypair.publicKeyHex, false)).toBe(
        false
      );
      expect(verifyAdminAuthorization(groupData, memberKeypair.publicKeyHex, true)).toBe(
        true
      );

      // ─── Step 4: Serialize/deserialize group data ────────────────
      const serialized = serializeMarmotGroupData(groupData);
      const deserialized = deserializeMarmotGroupData(serialized);
      expect(deserialized.name).toBe('Integration Test Group');
      expect(deserialized.adminPubkeys).toContain(adminKeypair.publicKeyHex);

      // ─── Step 5: Create Welcome event ────────────────────────────
      const welcomeData = randomBytes(256);
      const welcomeRumor = createWelcomeRumor(adminKeypair.publicKeyHex, {
        welcomeData,
        keyPackageEventId: 'test-kp-event-id',
        relays: ['wss://relay1.example.com'],
      });

      const welcomeValidation = validateWelcomeEvent(welcomeRumor, 'test-kp-event-id');
      expect(welcomeValidation.valid).toBe(true);

      const parsedWelcome = parseWelcomeEvent(welcomeRumor);
      expect(parsedWelcome.keyPackageEventId).toBe('test-kp-event-id');

      // ─── Step 6: Commit/Welcome ordering ─────────────────────────
      const tracker = new CommitWelcomeOrderTracker();
      const canSend = tracker.queueWelcome(
        'commit-event-id',
        memberKeypair.publicKeyHex,
        welcomeRumor
      );
      expect(canSend).toBe(false); // Not yet confirmed

      const released = tracker.confirmCommit('commit-event-id');
      expect(released.length).toBe(1);

      // ─── Step 7: Create Group Event ──────────────────────────────
      const groupEventResult = await createGroupEvent({
        encryptedContent: 'encrypted-mls-content',
        nostrGroupId: getNostrGroupIdHex(groupData),
      });

      expect(groupEventResult.event.kind).toBe(445);
      const parsed = parseGroupEvent(groupEventResult.event);
      expect(parsed.nostrGroupId).toBe(getNostrGroupIdHex(groupData));

      // ─── Step 8: Application Messages ────────────────────────────
      const appMsg = createApplicationMessage(
        adminKeypair.publicKeyHex,
        'Hello, Marmot group! 🦫'
      );

      const appValidation = validateApplicationMessage(appMsg);
      expect(appValidation.valid).toBe(true);

      expect(
        verifyApplicationMessageSender(appMsg.pubkey, adminKeypair.publicKeyHex)
      ).toBe(true);

      // Serialize and deserialize
      const msgJson = serializeApplicationMessage(appMsg);
      const desMsg = deserializeApplicationMessage(msgJson);
      expect(desMsg.content).toBe('Hello, Marmot group! 🦫');

      // ─── Step 9: Encrypt Media ───────────────────────────────────
      const mediaContent = new TextEncoder().encode('Fake JPEG data for testing');
      const exporterSecret = randomBytes(32);

      const mediaResult = encryptMedia({
        data: mediaContent,
        mimeType: 'image/jpeg',
        filename: 'marmot-photo.jpg',
        exporterSecret,
      });

      mediaResult.meta.url = 'https://blossom.example.com/' + mediaResult.encryptedHash;

      // Build and parse imeta tag
      const imetaTag = buildImetaTag(mediaResult.meta);
      const parsedMeta = parseImetaTag(imetaTag);
      expect(parsedMeta.mimeType).toBe('image/jpeg');
      expect(parsedMeta.filename).toBe('marmot-photo.jpg');

      // Decrypt media
      const decryptedMedia = decryptMedia({
        encryptedData: mediaResult.encryptedData,
        meta: mediaResult.meta,
        exporterSecret,
      });

      expect(new TextDecoder().decode(decryptedMedia)).toBe('Fake JPEG data for testing');

      // ─── Step 10: Group Image ────────────────────────────────────
      const imageData = new TextEncoder().encode('Fake group image data');
      const { encryptedImage, imageKey, imageNonce } = encryptGroupImage(imageData);

      const decryptedImage = decryptGroupImage(encryptedImage, imageKey, imageNonce);
      expect(new TextDecoder().decode(decryptedImage)).toBe('Fake group image data');

      // ─── Step 11: Commit race conditions ─────────────────────────
      const winner = selectWinningCommit([
        { createdAt: 2000, eventId: 'zzz' },
        { createdAt: 1000, eventId: 'abc' },
        { createdAt: 1000, eventId: 'def' },
      ]);
      expect(winner?.eventId).toBe('abc');

      // ─── Step 12: Clean up - delete KeyPackage ───────────────────
      const deletionEvent = createKeyPackageDeletionEvent(memberKeypair.publicKeyHex, [
        'test-kp-event-id',
      ]);
      expect(deletionEvent.kind).toBe(5);
    });
  });

  describe('Cross-module type compatibility', () => {
    it('should export all expected constants', () => {
      expect(MARMOT_EVENT_KINDS.KEY_PACKAGE).toBe(443);
      expect(MARMOT_EVENT_KINDS.WELCOME).toBe(444);
      expect(MARMOT_EVENT_KINDS.GROUP_EVENT).toBe(445);
      expect(MARMOT_EVENT_KINDS.KEY_PACKAGE_RELAY_LIST).toBe(10051);

      expect(MLS_EXTENSION_TYPES.MARMOT_GROUP_DATA).toBe(0xf2ee);
      expect(MLS_EXTENSION_TYPES.LAST_RESORT).toBe(0x000a);

      expect(MEDIA_VERSION).toBe('mip04-v2');
    });
  });

  describe('Ephemeral keypair uniqueness (security)', () => {
    it('should generate unique ephemeral keys for group events', async () => {
      const pubkeys = new Set<string>();
      for (let i = 0; i < 10; i++) {
        const result = await createGroupEvent({
          encryptedContent: `msg-${i}`,
          nostrGroupId: 'a'.repeat(64),
        });
        pubkeys.add(result.event.pubkey);
      }
      // All 10 should be unique
      expect(pubkeys.size).toBe(10);
    });
  });
});
