/**
 * Marmot Protocol Signer Abstraction
 *
 * Abstract signer interface compatible with nostr-tools.
 * Supports NIP-07 (browser extension), NIP-46 (remote/bunker), and private key signers.
 */

import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { v2 as nip44 } from 'nostr-tools/nip44';
import type { UnsignedEvent, SignedEvent } from './types.js';

// ─── Signer Interface ───────────────────────────────────────────────────────

/**
 * Abstract signer interface for Marmot Protocol.
 * Compatible with nostr-tools' signer conventions.
 */
export interface MarmotSigner {
  /** Get the signer's public key (hex-encoded, 32 bytes). */
  getPublicKey(): Promise<string>;

  /** Sign a Nostr event (returns the signed event with id and sig). */
  signEvent(event: UnsignedEvent): Promise<SignedEvent>;

  /**
   * NIP-44 encrypt content for a recipient.
   * Returns the encrypted string.
   */
  nip44Encrypt(pubkey: string, plaintext: string): Promise<string>;

  /**
   * NIP-44 decrypt content from a sender.
   * Returns the plaintext string.
   */
  nip44Decrypt(pubkey: string, ciphertext: string): Promise<string>;
}

// ─── Private Key Signer ─────────────────────────────────────────────────────

/**
 * Event serialization for computing event ID (NIP-01).
 */
function serializeEvent(event: UnsignedEvent): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

/**
 * Compute the event hash (ID).
 */
function computeEventId(event: UnsignedEvent): string {
  const serialized = new TextEncoder().encode(serializeEvent(event));
  return bytesToHex(sha256(serialized));
}

/**
 * Signer using a raw private key.
 * Suitable for testing and backend use. NOT recommended for production browser use.
 */
export class PrivateKeySigner implements MarmotSigner {
  private readonly _privateKey: Uint8Array;
  private readonly _publicKeyHex: string;

  constructor(privateKeyHex: string) {
    this._privateKey = hexToBytes(privateKeyHex);
    // x-only public key
    const fullPubkey = schnorr.getPublicKey(this._privateKey);
    this._publicKeyHex = bytesToHex(fullPubkey);
  }

  async getPublicKey(): Promise<string> {
    return this._publicKeyHex;
  }

  async signEvent(event: UnsignedEvent): Promise<SignedEvent> {
    const withPubkey = { ...event, pubkey: this._publicKeyHex };
    const id = computeEventId(withPubkey);
    const sigBytes = schnorr.sign(id, this._privateKey);
    const sig = bytesToHex(sigBytes);
    return { ...withPubkey, id, sig };
  }

  async nip44Encrypt(pubkey: string, plaintext: string): Promise<string> {
    const conversationKey = nip44.utils.getConversationKey(this._privateKey, pubkey);
    return nip44.encrypt(plaintext, conversationKey);
  }

  async nip44Decrypt(pubkey: string, ciphertext: string): Promise<string> {
    const conversationKey = nip44.utils.getConversationKey(this._privateKey, pubkey);
    return nip44.decrypt(ciphertext, conversationKey);
  }

  /**
   * Get the private key hex (for testing only).
   */
  getPrivateKeyHex(): string {
    return bytesToHex(this._privateKey);
  }
}

// ─── NIP-07 Browser Extension Signer ────────────────────────────────────────

/**
 * NIP-07 window.nostr interface (browser extension signers like nos2x, Alby).
 */
interface Nip07Nostr {
  getPublicKey(): Promise<string>;
  signEvent(event: unknown): Promise<{ id: string; sig: string; pubkey: string }>;
  nip44?: {
    encrypt(pubkey: string, plaintext: string): Promise<string>;
    decrypt(pubkey: string, ciphertext: string): Promise<string>;
  };
}

/**
 * Signer that delegates to a NIP-07 browser extension.
 */
export class Nip07Signer implements MarmotSigner {
  private _getNostr(): Nip07Nostr {
    const g = globalThis as Record<string, unknown>;
    if (typeof g !== 'undefined' && 'nostr' in g && g['nostr']) {
      return g['nostr'] as Nip07Nostr;
    }
    throw new Error('NIP-07 signer not available (window.nostr not found)');
  }

  async getPublicKey(): Promise<string> {
    return this._getNostr().getPublicKey();
  }

  async signEvent(event: UnsignedEvent): Promise<SignedEvent> {
    const nostr = this._getNostr();
    const result = await nostr.signEvent(event);
    return {
      ...event,
      id: result.id,
      sig: result.sig,
      pubkey: result.pubkey,
    };
  }

  async nip44Encrypt(pubkey: string, plaintext: string): Promise<string> {
    const nostr = this._getNostr();
    if (!nostr.nip44?.encrypt) {
      throw new Error('NIP-44 encryption not supported by this NIP-07 extension');
    }
    return nostr.nip44.encrypt(pubkey, plaintext);
  }

  async nip44Decrypt(pubkey: string, ciphertext: string): Promise<string> {
    const nostr = this._getNostr();
    if (!nostr.nip44?.decrypt) {
      throw new Error('NIP-44 decryption not supported by this NIP-07 extension');
    }
    return nostr.nip44.decrypt(pubkey, ciphertext);
  }
}

// ─── NIP-46 Remote Signer ───────────────────────────────────────────────────

/**
 * NIP-46 remote signer configuration.
 */
export interface Nip46Config {
  /** Remote signer public key */
  remotePubkey: string;
  /** Relay URL for NIP-46 communication */
  relayUrl: string;
  /** Secret for authentication */
  secret?: string;
  /** Client keypair for NIP-46 communication */
  clientPrivateKey?: string;
}

/**
 * Signer that communicates with a NIP-46 remote signer (bunker).
 * This is a skeleton — full NIP-46 implementation requires relay communication.
 */
export class Nip46Signer implements MarmotSigner {
  private readonly _config: Nip46Config;

  constructor(config: Nip46Config) {
    this._config = config;
  }

  async getPublicKey(): Promise<string> {
    // In a full implementation, this would communicate with the remote signer
    return this._config.remotePubkey;
  }

  async signEvent(_event: UnsignedEvent): Promise<SignedEvent> {
    void _event;
    throw new Error(
      'NIP-46 signEvent not yet implemented. ' +
        'Requires relay communication with the remote signer. ' +
        `Remote pubkey: ${this._config.remotePubkey}, Relay: ${this._config.relayUrl}`
    );
  }

  async nip44Encrypt(_pubkey: string, _plaintext: string): Promise<string> {
    void _pubkey;
    void _plaintext;
    throw new Error('NIP-46 nip44Encrypt not yet implemented');
  }

  async nip44Decrypt(_pubkey: string, _ciphertext: string): Promise<string> {
    void _pubkey;
    void _ciphertext;
    throw new Error('NIP-46 nip44Decrypt not yet implemented');
  }

  /** Get the NIP-46 configuration. */
  getConfig(): Nip46Config {
    return { ...this._config };
  }
}

// ─── Helper: Compute Event ID ───────────────────────────────────────────────

/**
 * Compute the event ID for an unsigned event.
 */
export { computeEventId };
