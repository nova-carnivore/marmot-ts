/**
 * KeyPackage Lifecycle Manager
 *
 * High-level KeyPackage management: fetching from relays, validation,
 * extension checking, and availability tracking.
 *
 * @packageDocumentation
 */

import type { ParsedKeyPackage, SignedEvent } from './types.js';
import { MARMOT_EVENT_KINDS, MLS_EXTENSION_TYPES } from './types.js';
import { parseKeyPackageEvent, hasRequiredMarmotExtensions } from './mip00.js';
import { parseKeyPackageBytes, parseKeyPackageRaw } from './mls.js';
import type { ParsedKeyPackageRaw } from './mls.js';
import { isValidPubkey } from './utils.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Information about a KeyPackage with its validation status.
 */
export interface KeyPackageValidationResult {
  /** The parsed KeyPackage event data */
  parsed: ParsedKeyPackage;
  /** Whether the KeyPackage has required Marmot extensions (0xf2ee, 0x000a) */
  hasRequiredExtensions: boolean;
  /** Raw parsed KeyPackage data (capabilities, extensions) */
  rawParsed?: ParsedKeyPackageRaw;
  /** Validation errors, if any */
  errors: string[];
}

/**
 * Options for fetching KeyPackages.
 */
export interface FetchKeyPackagesOptions {
  /** Maximum number of KeyPackages to fetch per pubkey */
  limit?: number;
  /** Only include KeyPackages newer than this timestamp (unix seconds) */
  since?: number;
  /** Filter by ciphersuite hex (e.g., '0x0001') */
  ciphersuite?: string;
}

// ─── KeyPackage Manager ─────────────────────────────────────────────────────

/**
 * KeyPackage lifecycle manager.
 *
 * Provides high-level operations for KeyPackage validation and extension
 * checking. Relay communication is left to the consumer (uses callbacks)
 * to avoid coupling with any specific relay library.
 */
export class KeyPackageManager {
  /**
   * Validate a KeyPackage event and check required extensions.
   *
   * @param event - A signed kind:443 event
   * @returns Validation result with parsed data and extension status
   */
  validateKeyPackageEvent(event: SignedEvent): KeyPackageValidationResult {
    const errors: string[] = [];
    let hasRequired = false;
    let rawParsed: ParsedKeyPackageRaw | undefined;

    // Parse the Nostr event
    let parsed: ParsedKeyPackage;
    try {
      parsed = parseKeyPackageEvent(event);
    } catch (err) {
      return {
        parsed: {
          eventId: event.id ?? '',
          pubkey: event.pubkey ?? '',
          keyPackageData: new Uint8Array(0),
          protocolVersion: '',
          ciphersuite: '',
          extensions: [],
          encoding: 'base64',
          relays: [],
          createdAt: event.created_at ?? 0,
        },
        hasRequiredExtensions: false,
        errors: [`Failed to parse KeyPackage event: ${err instanceof Error ? err.message : String(err)}`],
      };
    }

    // Check kind
    if (event.kind !== MARMOT_EVENT_KINDS.KEY_PACKAGE) {
      errors.push(`Expected kind ${MARMOT_EVENT_KINDS.KEY_PACKAGE}, got ${event.kind}`);
    }

    // Validate the MLS KeyPackage bytes
    try {
      const mlsKp = parseKeyPackageBytes(parsed.keyPackageData);
      void mlsKp; // We just need it to not throw

      // Parse raw for extension checking
      rawParsed = parseKeyPackageRaw(parsed.keyPackageData);
    } catch (err) {
      errors.push(`Invalid MLS KeyPackage data: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Check required Marmot extensions
    hasRequired = this.hasRequiredExtensions(parsed);

    return {
      parsed,
      hasRequiredExtensions: hasRequired,
      rawParsed,
      errors,
    };
  }

  /**
   * Check whether a parsed KeyPackage has required Marmot extensions.
   *
   * Per MIP-00, Marmot KeyPackages MUST include:
   * - 0xf2ee (marmot_group_data)
   * - 0x000a (last_resort)
   *
   * @param parsed - Parsed KeyPackage data
   * @returns true if both required extensions are present
   */
  hasRequiredExtensions(parsed: ParsedKeyPackage): boolean {
    return hasRequiredMarmotExtensions(parsed);
  }

  /**
   * Check whether a raw KeyPackage has the required Marmot extensions
   * in its capabilities.
   *
   * @param rawParsed - Raw parsed KeyPackage with capabilities
   * @returns true if both required extensions are in capabilities
   */
  hasRequiredCapabilityExtensions(rawParsed: ParsedKeyPackageRaw): boolean {
    if (!rawParsed.capabilities) return false;
    const capExts = rawParsed.capabilities.extensions;
    return (
      capExts.includes(MLS_EXTENSION_TYPES.MARMOT_GROUP_DATA) &&
      capExts.includes(MLS_EXTENSION_TYPES.LAST_RESORT)
    );
  }

  /**
   * Filter KeyPackage events to only valid ones with required extensions.
   *
   * @param events - Array of signed kind:443 events
   * @returns Array of validated KeyPackages with required extensions
   */
  filterValid(events: SignedEvent[]): KeyPackageValidationResult[] {
    const results: KeyPackageValidationResult[] = [];

    for (const event of events) {
      const result = this.validateKeyPackageEvent(event);
      if (result.errors.length === 0 && result.hasRequiredExtensions) {
        results.push(result);
      }
    }

    return results;
  }

  /**
   * Select the best KeyPackage from a set of events for a given pubkey.
   *
   * Strategy: most recent valid KeyPackage with required extensions.
   *
   * @param events - Array of signed kind:443 events
   * @param pubkey - Target pubkey to find a KeyPackage for
   * @returns The best KeyPackage validation result, or null if none valid
   */
  selectBest(events: SignedEvent[], pubkey: string): KeyPackageValidationResult | null {
    if (!isValidPubkey(pubkey)) return null;

    const valid = this.filterValid(events)
      .filter((r) => r.parsed.pubkey === pubkey)
      .sort((a, b) => b.parsed.createdAt - a.parsed.createdAt);

    return valid[0] ?? null;
  }

  /**
   * Check KeyPackage availability for a list of pubkeys.
   *
   * @param events - Array of signed kind:443 events
   * @param pubkeys - Array of pubkeys to check
   * @returns Map of pubkey → boolean (has valid KeyPackage)
   */
  checkAvailability(
    events: SignedEvent[],
    pubkeys: string[]
  ): Map<string, boolean> {
    const result = new Map<string, boolean>();
    const validByPubkey = new Map<string, boolean>();

    for (const event of events) {
      const validation = this.validateKeyPackageEvent(event);
      if (validation.errors.length === 0 && validation.hasRequiredExtensions) {
        validByPubkey.set(validation.parsed.pubkey, true);
      }
    }

    for (const pk of pubkeys) {
      result.set(pk, validByPubkey.get(pk) ?? false);
    }

    return result;
  }

  /**
   * Build a Nostr subscription filter for fetching KeyPackage events.
   *
   * @param pubkeys - Pubkeys to fetch KeyPackages for
   * @param options - Optional fetch options
   * @returns Nostr filter object for use with relay subscriptions
   */
  buildSubscriptionFilter(
    pubkeys: string[],
    options?: FetchKeyPackagesOptions
  ): Record<string, unknown> {
    const filter: Record<string, unknown> = {
      kinds: [MARMOT_EVENT_KINDS.KEY_PACKAGE],
      authors: pubkeys,
    };

    if (options?.limit) {
      filter['limit'] = options.limit;
    }

    if (options?.since) {
      filter['since'] = options.since;
    }

    return filter;
  }
}
