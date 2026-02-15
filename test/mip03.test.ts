import { describe, it, expect } from 'vitest';
import {
  createGroupEvent,
  parseGroupEvent,
  deriveEncryptionKeypair,
  createApplicationMessage,
  createReactionMessage,
  validateApplicationMessage,
  verifyApplicationMessageSender,
  serializeApplicationMessage,
  deserializeApplicationMessage,
  compareCommitPriority,
  selectWinningCommit,
  CommitOrderTracker,
  isValidSelfUpdate,
} from '../src/mip03.js';
import { MARMOT_EVENT_KINDS } from '../src/types.js';
import type { CommitPriority } from '../src/types.js';
import { bytesToHex } from '../src/utils.js';

describe('MIP-03: Group Messages', () => {
  const testPubkey = 'a'.repeat(64);
  const testGroupId = 'b'.repeat(64);

  describe('createGroupEvent', () => {
    it('should create event with ephemeral keypair', async () => {
      const result = await createGroupEvent({
        encryptedContent: 'encrypted-mls-message',
        nostrGroupId: testGroupId,
      });

      expect(result.event.kind).toBe(MARMOT_EVENT_KINDS.GROUP_EVENT);
      expect(result.event.content).toBe('encrypted-mls-message');
      expect(result.event.id).toBeDefined();
      expect(result.event.sig).toBeDefined();
      expect(result.ephemeralPrivateKey.length).toBe(64);

      // Check h tag
      const hTag = result.event.tags.find((t) => t[0] === 'h');
      expect(hTag?.[1]).toBe(testGroupId);
    });

    it('should generate different ephemeral keys each call', async () => {
      const a = await createGroupEvent({
        encryptedContent: 'msg1',
        nostrGroupId: testGroupId,
      });
      const b = await createGroupEvent({
        encryptedContent: 'msg2',
        nostrGroupId: testGroupId,
      });

      expect(a.event.pubkey).not.toBe(b.event.pubkey);
      expect(a.ephemeralPrivateKey).not.toBe(b.ephemeralPrivateKey);
    });
  });

  describe('parseGroupEvent', () => {
    it('should parse a group event', async () => {
      const { event } = await createGroupEvent({
        encryptedContent: 'test-content',
        nostrGroupId: testGroupId,
      });

      const parsed = parseGroupEvent(event);
      expect(parsed.encryptedContent).toBe('test-content');
      expect(parsed.nostrGroupId).toBe(testGroupId);
      expect(parsed.ephemeralPubkey.length).toBe(64);
    });

    it('should reject wrong kind', () => {
      expect(() =>
        parseGroupEvent({
          id: 'test',
          kind: 1,
          created_at: 1000,
          pubkey: testPubkey,
          content: '',
          tags: [],
          sig: 'test',
        })
      ).toThrow('Expected kind 445');
    });

    it('should reject missing h tag', () => {
      expect(() =>
        parseGroupEvent({
          id: 'test',
          kind: MARMOT_EVENT_KINDS.GROUP_EVENT,
          created_at: 1000,
          pubkey: testPubkey,
          content: 'test',
          tags: [],
          sig: 'test',
        })
      ).toThrow('Missing h tag');
    });
  });

  describe('deriveEncryptionKeypair', () => {
    it('should derive keypair from exporter secret', () => {
      const secret = new Uint8Array(32).fill(0x42);
      const { privateKeyHex, publicKeyHex } = deriveEncryptionKeypair(secret);

      expect(privateKeyHex.length).toBe(64);
      expect(publicKeyHex.length).toBe(64);
      expect(privateKeyHex).toBe(bytesToHex(secret));
    });

    it('should reject wrong-length secret', () => {
      expect(() => deriveEncryptionKeypair(new Uint8Array(16))).toThrow(
        'exporter_secret must be 32 bytes'
      );
    });

    it('should produce consistent output', () => {
      const secret = new Uint8Array(32).fill(0x42);
      const a = deriveEncryptionKeypair(secret);
      const b = deriveEncryptionKeypair(secret);
      expect(a.publicKeyHex).toBe(b.publicKeyHex);
    });
  });

  describe('createApplicationMessage', () => {
    it('should create unsigned chat message', () => {
      const msg = createApplicationMessage(testPubkey, 'Hello!');

      expect(msg.kind).toBe(9);
      expect(msg.pubkey).toBe(testPubkey);
      expect(msg.content).toBe('Hello!');
      expect(msg.id).toBeDefined();
      expect('sig' in msg && msg.sig).toBeFalsy();
    });

    it('should support custom kinds', () => {
      const msg = createApplicationMessage(testPubkey, 'data', 42);
      expect(msg.kind).toBe(42);
    });

    it('should reject h tags', () => {
      expect(() =>
        createApplicationMessage(testPubkey, 'test', 9, [['h', 'group-id']])
      ).toThrow('MUST NOT include h tags');
    });

    it('should reject invalid pubkey', () => {
      expect(() => createApplicationMessage('invalid', 'test')).toThrow(
        'Invalid sender pubkey'
      );
    });
  });

  describe('createReactionMessage', () => {
    it('should create reaction event', () => {
      const msg = createReactionMessage(testPubkey, 'event-123', 'b'.repeat(64), '🦫');

      expect(msg.kind).toBe(7);
      expect(msg.content).toBe('🦫');
      expect(msg.tags).toContainEqual(['e', 'event-123']);
      expect(msg.tags).toContainEqual(['p', 'b'.repeat(64)]);
    });

    it('should default to + reaction', () => {
      const msg = createReactionMessage(testPubkey, 'event-123', 'b'.repeat(64));
      expect(msg.content).toBe('+');
    });
  });

  describe('validateApplicationMessage', () => {
    it('should accept valid unsigned message', () => {
      const msg = createApplicationMessage(testPubkey, 'test');
      const result = validateApplicationMessage(msg);
      expect(result.valid).toBe(true);
    });

    it('should reject signed message', () => {
      const msg = {
        kind: 9,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'test',
        tags: [],
        sig: 'some-sig',
      };
      const result = validateApplicationMessage(msg);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('MUST NOT be signed'))).toBe(true);
    });

    it('should reject h tags', () => {
      const msg = {
        kind: 9,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'test',
        tags: [['h', 'group-id']],
      };
      const result = validateApplicationMessage(msg);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('h tags'))).toBe(true);
    });
  });

  describe('verifyApplicationMessageSender', () => {
    it('should verify matching sender', () => {
      expect(verifyApplicationMessageSender(testPubkey, testPubkey)).toBe(true);
    });

    it('should reject mismatched sender', () => {
      expect(verifyApplicationMessageSender(testPubkey, 'c'.repeat(64))).toBe(false);
    });

    it('should reject invalid pubkeys', () => {
      expect(verifyApplicationMessageSender('invalid', testPubkey)).toBe(false);
    });
  });

  describe('serializeApplicationMessage / deserializeApplicationMessage', () => {
    it('should roundtrip', () => {
      const msg = createApplicationMessage(testPubkey, 'Hello 🦫');
      const json = serializeApplicationMessage(msg);
      const deserialized = deserializeApplicationMessage(json);

      expect(deserialized.kind).toBe(msg.kind);
      expect(deserialized.content).toBe(msg.content);
      expect(deserialized.pubkey).toBe(msg.pubkey);
    });

    it('should reject signed message in deserialization', () => {
      const json = JSON.stringify({
        kind: 9,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'test',
        tags: [],
        sig: 'some-sig',
      });
      expect(() => deserializeApplicationMessage(json)).toThrow('MUST NOT be signed');
    });
  });

  describe('compareCommitPriority', () => {
    it('should prefer earlier timestamp', () => {
      const a: CommitPriority = { createdAt: 1000, eventId: 'zzz' };
      const b: CommitPriority = { createdAt: 2000, eventId: 'aaa' };
      expect(compareCommitPriority(a, b)).toBeLessThan(0);
    });

    it('should prefer smaller ID on tie', () => {
      const a: CommitPriority = { createdAt: 1000, eventId: 'aaa' };
      const b: CommitPriority = { createdAt: 1000, eventId: 'bbb' };
      expect(compareCommitPriority(a, b)).toBeLessThan(0);
    });
  });

  describe('selectWinningCommit', () => {
    it('should select the winning commit', () => {
      const commits: CommitPriority[] = [
        { createdAt: 2000, eventId: 'bbb' },
        { createdAt: 1000, eventId: 'ccc' },
        { createdAt: 1000, eventId: 'aaa' },
      ];

      const winner = selectWinningCommit(commits);
      expect(winner?.eventId).toBe('aaa');
      expect(winner?.createdAt).toBe(1000);
    });

    it('should return null for empty array', () => {
      expect(selectWinningCommit([])).toBeNull();
    });
  });

  describe('CommitOrderTracker', () => {
    it('should track pending commits', () => {
      const tracker = new CommitOrderTracker();
      expect(tracker.isConfirmed('commit-1')).toBe(false);
    });

    it('should confirm commits', () => {
      const tracker = new CommitOrderTracker();
      tracker.addPendingCommit({
        id: 'commit-1',
        kind: 445,
        created_at: 1000,
        pubkey: testPubkey,
        content: '',
        tags: [],
        sig: 'test',
      });

      expect(tracker.confirmCommit('commit-1')).toBe(true);
      expect(tracker.isConfirmed('commit-1')).toBe(true);
    });

    it('should identify initial commit', () => {
      const tracker = new CommitOrderTracker();
      expect(tracker.isInitialCommit(0)).toBe(true);
      expect(tracker.isInitialCommit(1)).toBe(false);
    });
  });

  describe('isValidSelfUpdate', () => {
    it('should accept single-proposal self update', () => {
      expect(isValidSelfUpdate(testPubkey, testPubkey, 1)).toBe(true);
    });

    it('should reject multi-proposal', () => {
      expect(isValidSelfUpdate(testPubkey, testPubkey, 2)).toBe(false);
    });

    it('should reject updating someone else', () => {
      expect(isValidSelfUpdate(testPubkey, 'c'.repeat(64), 1)).toBe(false);
    });
  });
});
