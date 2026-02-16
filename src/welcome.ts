/**
 * Welcome — Complete Welcome publishing flow
 *
 * High-level helpers for the full Welcome event lifecycle:
 * Encode → Gift-wrap → Publish-ready events.
 *
 * @packageDocumentation
 */

import type { UnsignedEvent, SignedEvent } from './types.js';
import type { MarmotSigner } from './signer.js';
import { giftWrapWelcome, createWelcomeRumor } from './mip02.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Information about a Welcome to send.
 */
export interface WelcomeInfo {
  /** Recipient's pubkey (hex) */
  recipientPubkey: string;
  /** The unsigned Welcome rumor event */
  welcomeRumor: UnsignedEvent;
}

/**
 * Result of publishing a Welcome event.
 */
export interface PublishWelcomeResult {
  /** Recipient's pubkey */
  recipientPubkey: string;
  /** The gift-wrapped event ready for relay publishing */
  giftWrap: SignedEvent;
  /** Whether wrapping succeeded */
  success: boolean;
  /** Error message if wrapping failed */
  error?: string;
}

/**
 * Options for creating Welcomes from raw data.
 */
export interface CreateWelcomesOptions {
  /** Admin/sender pubkey */
  senderPubkey: string;
  /** Encoded MLS Welcome bytes */
  welcomeBytes: Uint8Array;
  /** Relay URLs for the group */
  relays: string[];
  /** Members to send Welcomes to: pubkey → KeyPackage event ID */
  recipients: Array<{
    pubkey: string;
    keyPackageEventId: string;
  }>;
}

// ─── Welcome Flow ───────────────────────────────────────────────────────────

/**
 * Gift-wrap multiple Welcome events for publishing.
 *
 * Takes pre-created Welcome rumors and wraps each one in NIP-59
 * gift wrapping. Returns publish-ready events.
 *
 * @param signer - Signer for the admin sending the Welcomes
 * @param welcomes - Array of Welcome info (recipient + rumor)
 * @returns Array of results (gift-wrapped events or errors)
 */
export async function wrapWelcomes(
  signer: MarmotSigner,
  welcomes: WelcomeInfo[]
): Promise<PublishWelcomeResult[]> {
  const results: PublishWelcomeResult[] = [];

  for (const welcome of welcomes) {
    try {
      const giftWrap = await giftWrapWelcome(
        signer,
        welcome.recipientPubkey,
        welcome.welcomeRumor
      );

      results.push({
        recipientPubkey: welcome.recipientPubkey,
        giftWrap,
        success: true,
      });
    } catch (err) {
      results.push({
        recipientPubkey: welcome.recipientPubkey,
        giftWrap: {} as SignedEvent,
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return results;
}

/**
 * Create and gift-wrap Welcome events from raw Welcome bytes.
 *
 * Complete flow: creates Welcome rumors → gift wraps each one.
 * This is the highest-level helper for sending Welcomes.
 *
 * @param signer - Signer for the admin
 * @param options - Welcome creation options
 * @returns Array of publish-ready results
 */
export async function createAndWrapWelcomes(
  signer: MarmotSigner,
  options: CreateWelcomesOptions
): Promise<PublishWelcomeResult[]> {
  const welcomes: WelcomeInfo[] = options.recipients.map((recipient) => {
    const rumor = createWelcomeRumor(options.senderPubkey, {
      welcomeData: options.welcomeBytes,
      keyPackageEventId: recipient.keyPackageEventId,
      relays: options.relays,
    });

    return {
      recipientPubkey: recipient.pubkey,
      welcomeRumor: rumor,
    };
  });

  return wrapWelcomes(signer, welcomes);
}
