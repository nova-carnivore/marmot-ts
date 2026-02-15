import { describe, it, expect } from 'vitest';
import {
  createWelcomeRumor,
  parseWelcomeEvent,
  CommitWelcomeOrderTracker,
  validateWelcomeEvent,
  isInitialGroupCreation,
} from '../src/mip02.js';
import { MARMOT_EVENT_KINDS } from '../src/types.js';
import type { UnsignedEvent } from '../src/types.js';

describe('MIP-02: Welcome Events', () => {
  const testPubkey = 'a'.repeat(64);
  const testWelcomeData = new Uint8Array(64).fill(0xbb);

  describe('createWelcomeRumor', () => {
    it('should create unsigned Welcome event', () => {
      const rumor = createWelcomeRumor(testPubkey, {
        welcomeData: testWelcomeData,
        keyPackageEventId: 'kp-event-123',
        relays: ['wss://relay1.com'],
      });

      expect(rumor.kind).toBe(MARMOT_EVENT_KINDS.WELCOME);
      expect(rumor.pubkey).toBe(testPubkey);
      expect(rumor.content.length).toBeGreaterThan(0);
      expect('sig' in rumor).toBe(false);

      // Check tags
      const eTag = rumor.tags.find((t) => t[0] === 'e');
      expect(eTag?.[1]).toBe('kp-event-123');

      const relaysTag = rumor.tags.find((t) => t[0] === 'relays');
      expect(relaysTag).toContain('wss://relay1.com');

      const encodingTag = rumor.tags.find((t) => t[0] === 'encoding');
      expect(encodingTag?.[1]).toBe('base64');
    });

    it('should support hex encoding', () => {
      const rumor = createWelcomeRumor(testPubkey, {
        welcomeData: testWelcomeData,
        keyPackageEventId: 'kp-event-123',
        relays: ['wss://relay1.com'],
        encoding: 'hex',
      });

      const encodingTag = rumor.tags.find((t) => t[0] === 'encoding');
      expect(encodingTag?.[1]).toBe('hex');
    });
  });

  describe('parseWelcomeEvent', () => {
    it('should parse a created Welcome event', () => {
      const rumor = createWelcomeRumor(testPubkey, {
        welcomeData: testWelcomeData,
        keyPackageEventId: 'kp-event-456',
        relays: ['wss://relay1.com', 'wss://relay2.com'],
      });

      const parsed = parseWelcomeEvent(rumor);
      expect(parsed.keyPackageEventId).toBe('kp-event-456');
      expect(parsed.relays).toEqual(['wss://relay1.com', 'wss://relay2.com']);
      expect(parsed.encoding).toBe('base64');
      expect(parsed.welcomeData.length).toBe(testWelcomeData.length);
    });

    it('should reject wrong event kind', () => {
      const event: UnsignedEvent = {
        kind: 1,
        created_at: 1000,
        pubkey: testPubkey,
        content: '',
        tags: [],
      };
      expect(() => parseWelcomeEvent(event)).toThrow('Expected kind 444');
    });

    it('should reject missing e tag', () => {
      const event: UnsignedEvent = {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'dGVzdA==',
        tags: [['encoding', 'base64']],
      };
      expect(() => parseWelcomeEvent(event)).toThrow('Missing e tag');
    });
  });

  describe('CommitWelcomeOrderTracker', () => {
    it('should track confirmed commits', () => {
      const tracker = new CommitWelcomeOrderTracker();
      expect(tracker.isCommitConfirmed('commit-1')).toBe(false);
      tracker.confirmCommit('commit-1');
      expect(tracker.isCommitConfirmed('commit-1')).toBe(true);
    });

    it('should queue welcomes until commit confirmed', () => {
      const tracker = new CommitWelcomeOrderTracker();
      const welcomeRumor: UnsignedEvent = {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'test',
        tags: [],
      };

      // Queue a welcome - should return false (not yet confirmed)
      const ready = tracker.queueWelcome('commit-1', 'recipient-pubkey', welcomeRumor);
      expect(ready).toBe(false);
      expect(tracker.pendingCount).toBe(1);

      // Confirm the commit - should return the pending welcomes
      const pending = tracker.confirmCommit('commit-1');
      expect(pending.length).toBe(1);
      expect(pending[0]!.recipientPubkey).toBe('recipient-pubkey');
      expect(tracker.pendingCount).toBe(0);
    });

    it('should allow immediate send when commit already confirmed', () => {
      const tracker = new CommitWelcomeOrderTracker();
      tracker.confirmCommit('commit-1');

      const ready = tracker.queueWelcome('commit-1', 'recipient', {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'test',
        tags: [],
      });
      expect(ready).toBe(true);
    });

    it('should handle multiple welcomes for same commit', () => {
      const tracker = new CommitWelcomeOrderTracker();

      tracker.queueWelcome('commit-1', 'recipient-a', {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'a',
        tags: [],
      });
      tracker.queueWelcome('commit-1', 'recipient-b', {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: 'b',
        tags: [],
      });

      expect(tracker.pendingCount).toBe(2);

      const pending = tracker.confirmCommit('commit-1');
      expect(pending.length).toBe(2);
    });
  });

  describe('validateWelcomeEvent', () => {
    it('should validate correct Welcome event', () => {
      const rumor = createWelcomeRumor(testPubkey, {
        welcomeData: testWelcomeData,
        keyPackageEventId: 'kp-123',
        relays: ['wss://relay1.com'],
      });

      const result = validateWelcomeEvent(rumor);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should detect wrong kind', () => {
      const event: UnsignedEvent = {
        kind: 1,
        created_at: 1000,
        pubkey: testPubkey,
        content: '',
        tags: [],
      };

      const result = validateWelcomeEvent(event);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('Invalid kind'))).toBe(true);
    });

    it('should detect signed events', () => {
      const signedEvent = {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: '',
        tags: [
          ['e', 'kp-123'],
          ['relays', 'wss://relay1.com'],
        ],
        sig: 'some-signature',
      };

      const result = validateWelcomeEvent(signedEvent);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('MUST NOT be signed'))).toBe(true);
    });

    it('should detect missing e tag', () => {
      const event: UnsignedEvent = {
        kind: MARMOT_EVENT_KINDS.WELCOME,
        created_at: 1000,
        pubkey: testPubkey,
        content: '',
        tags: [['relays', 'wss://relay1.com']],
      };

      const result = validateWelcomeEvent(event);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('Missing e tag'))).toBe(true);
    });

    it('should check expected KeyPackage ID', () => {
      const rumor = createWelcomeRumor(testPubkey, {
        welcomeData: testWelcomeData,
        keyPackageEventId: 'kp-123',
        relays: ['wss://relay1.com'],
      });

      const result = validateWelcomeEvent(rumor, 'kp-999');
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('KeyPackage mismatch'))).toBe(true);
    });
  });

  describe('isInitialGroupCreation', () => {
    it('should return true for epoch 0', () => {
      expect(isInitialGroupCreation(0)).toBe(true);
    });

    it('should return false for later epochs', () => {
      expect(isInitialGroupCreation(1)).toBe(false);
      expect(isInitialGroupCreation(10)).toBe(false);
    });
  });
});
