/**
 * Group Management — Add/leave helpers
 *
 * High-level group management operations for the Marmot Protocol.
 * Provides member addition with KeyPackage fetching, MLS commit creation,
 * and Welcome event generation.
 *
 * @packageDocumentation
 */

import type { UnsignedEvent } from './types.js';
import { addMlsGroupMembers, encodeWelcome, parseKeyPackageBytes } from './mls.js';
import type {
  ClientState,
  KeyPackage,
  AddMembersResult,
  CiphersuiteName,
} from './mls.js';
import { createWelcomeRumor } from './mip02.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Result of adding members to a group.
 */
export interface AddGroupMembersResult {
  /** Pubkeys successfully added */
  added: string[];
  /** Pubkeys that failed (no KeyPackage, parse error, etc.) */
  failed: string[];
  /** Welcome rumor events for each added member (ready for gift wrapping) */
  welcomeRumors: Array<{
    recipientPubkey: string;
    keyPackageEventId: string;
    rumor: UnsignedEvent;
  }>;
  /** Updated MLS group state */
  newState: ClientState;
  /** Encoded state for persistence */
  encodedState: Uint8Array;
  /** Updated exporter secret */
  exporterSecret: Uint8Array;
  /** Raw MLS Welcome for custom handling */
  welcomeBytes: Uint8Array;
}

/**
 * A fetched KeyPackage with metadata.
 */
export interface FetchedKeyPackage {
  /** The member's pubkey */
  pubkey: string;
  /** The KeyPackage event ID (for Welcome event reference) */
  eventId: string;
  /** Raw KeyPackage bytes */
  keyPackageBytes: Uint8Array;
  /** Content encoding from the event */
  encoding: 'base64' | 'hex';
}

/**
 * Options for adding group members.
 */
export interface AddGroupMembersOptions {
  /** Current MLS group state */
  mlsState: ClientState;
  /** Ciphersuite name (optional) */
  ciphersuiteName?: CiphersuiteName;
  /** Relay URLs for the group */
  relays: string[];
  /** The admin/sender's pubkey */
  senderPubkey: string;
}

// ─── Add Members ────────────────────────────────────────────────────────────

/**
 * Add members to an MLS group.
 *
 * This function handles the full flow:
 * 1. Parse KeyPackages from fetched data
 * 2. Create MLS Add commit
 * 3. Encode Welcome
 * 4. Create Welcome rumor events (ready for NIP-59 gift wrapping)
 *
 * Note: This does NOT handle relay fetching or gift wrapping — those are
 * left to the consumer to keep this function relay-library-agnostic.
 *
 * @param fetchedKeyPackages - Pre-fetched KeyPackages for the new members
 * @param options - Group and MLS configuration
 * @returns Result with added/failed members, Welcome rumors, and updated state
 */
export async function addGroupMembers(
  fetchedKeyPackages: FetchedKeyPackage[],
  options: AddGroupMembersOptions
): Promise<AddGroupMembersResult> {
  const { mlsState, ciphersuiteName, relays, senderPubkey } = options;

  const added: string[] = [];
  const failed: string[] = [];
  const parsedKeyPackages: Array<{
    pubkey: string;
    eventId: string;
    mlsKeyPackage: KeyPackage;
  }> = [];

  // Parse all fetched KeyPackages
  for (const fkp of fetchedKeyPackages) {
    try {
      const mlsKp = parseKeyPackageBytes(fkp.keyPackageBytes);
      parsedKeyPackages.push({
        pubkey: fkp.pubkey,
        eventId: fkp.eventId,
        mlsKeyPackage: mlsKp,
      });
    } catch (err) {
      console.warn(
        `[GroupMgmt] Failed to parse KeyPackage for ${fkp.pubkey.slice(0, 8)}:`,
        err
      );
      failed.push(fkp.pubkey);
    }
  }

  if (parsedKeyPackages.length === 0) {
    return {
      added,
      failed,
      welcomeRumors: [],
      newState: mlsState,
      encodedState: new Uint8Array(0),
      exporterSecret: new Uint8Array(0),
      welcomeBytes: new Uint8Array(0),
    };
  }

  // Add all parsed KeyPackages to the MLS group
  let addResult: AddMembersResult;
  try {
    addResult = await addMlsGroupMembers(
      mlsState,
      parsedKeyPackages.map((m) => m.mlsKeyPackage),
      ciphersuiteName
    );
  } catch (err) {
    // If MLS add fails, all members fail
    for (const pkp of parsedKeyPackages) {
      failed.push(pkp.pubkey);
    }
    return {
      added,
      failed,
      welcomeRumors: [],
      newState: mlsState,
      encodedState: new Uint8Array(0),
      exporterSecret: new Uint8Array(0),
      welcomeBytes: new Uint8Array(0),
    };
  }

  // Encode Welcome
  const welcomeBytes = encodeWelcome(addResult.welcome);

  // Create Welcome rumor events for each added member
  const welcomeRumors: AddGroupMembersResult['welcomeRumors'] = [];
  for (const pkp of parsedKeyPackages) {
    const rumor = createWelcomeRumor(senderPubkey, {
      welcomeData: welcomeBytes,
      keyPackageEventId: pkp.eventId,
      relays,
    });
    welcomeRumors.push({
      recipientPubkey: pkp.pubkey,
      keyPackageEventId: pkp.eventId,
      rumor,
    });
    added.push(pkp.pubkey);
  }

  return {
    added,
    failed,
    welcomeRumors,
    newState: addResult.newState,
    encodedState: addResult.encodedState,
    exporterSecret: addResult.exporterSecret,
    welcomeBytes,
  };
}

// ─── Leave Group ────────────────────────────────────────────────────────────

/**
 * Leave a group (local cleanup only).
 *
 * NOTE: MLS self-remove is not yet supported in ts-mls.
 * This function is a placeholder that documents the intended behavior.
 * Currently, leaving a group only requires local state cleanup which
 * must be handled by the consumer (e.g., removing IndexedDB entries).
 *
 * When ts-mls adds self-remove support, this function will:
 * 1. Create an MLS remove proposal for self
 * 2. Create and sign a Commit
 * 3. Publish the Commit to relays
 *
 * @param _mlsState - Current MLS group state (unused until self-remove is supported)
 * @returns void — consumer must handle local state cleanup
 */
export async function leaveGroup(_mlsState: ClientState): Promise<void> {
  void _mlsState;
  // TODO: When ts-mls supports self-remove:
  // 1. const removeProposal = await createSelfRemove(mlsState);
  // 2. const commit = await createCommit(mlsState, [removeProposal]);
  // 3. Return the commit event for publishing
  //
  // For now, consumers should:
  // - Remove conversation from local store
  // - Clear MLS state from persistence (IndexedDB)
  // - Clear exporter secrets
}
