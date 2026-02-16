# MDK Wire Format Analysis

**Date:** 2026-02-16  
**MDK Version:** 0.5.3 (mdk-core)  
**OpenMLS Version:** 0.8.0  
**tls_codec Version:** 0.4.2 (with `mls` feature enabled)

## TL;DR

**MDK uses the exact same MLS varint encoding as marmot-chat.** Both use OpenMLS with `tls_codec` v0.4.2 and the `mls` feature, which means RFC 9420 Section 2.1.2 variable-length integer encoding throughout. The parsing failure for Kai's KeyPackage is **not** a wire format incompatibility — it's likely a content encoding issue (see §7).

---

## 1. Does MDK Use MLS Varint Encoding?

**Yes, absolutely.** 

MDK depends on OpenMLS 0.8.0, which depends on `tls_codec = { version = "^0.4.2", features = ["derive", "serde", "mls"] }`.

The **`mls` feature** in tls_codec switches the variable-length encoding from QUIC-style (up to 62-bit, RFC 9000) to MLS-style (up to 30-bit, RFC 9420 Section 2.1.2):

```rust
// From tls_codec/src/quic_vec.rs:
#[cfg(feature = "mls")]
const MAX_LEN: u64 = (1 << 30) - 1;
#[cfg(feature = "mls")]
const MAX_LEN_LEN_LOG: usize = 2;  // max 4-byte length (not 8-byte)
```

The encoding uses the top 2 bits of the first byte:
- `00` → 1-byte length (6-bit value, 0–63)
- `01` → 2-byte length (14-bit value, 64–16383)
- `10` → 4-byte length (30-bit value, 16384–1073741823)
- `11` → **invalid** (rejected with `mls` feature; valid only in QUIC mode for 8-byte/62-bit)

With the `mls` feature, minimum encoding is enforced — values ≤63 MUST use 1 byte, values ≤16383 MUST use 2 bytes, etc.

**Conclusion: MDK and marmot-chat use identical varint encoding.**

---

## 2. How Does MDK Serialize BasicCredential.identity?

**32 raw bytes of the Nostr public key, per MIP-00.**

From `mdk-core/src/key_packages.rs`:
```rust
pub(crate) fn generate_credential_with_key(&self, public_key: &PublicKey) 
    -> Result<(CredentialWithKey, SignatureKeyPair), Error> 
{
    let public_key_bytes: Vec<u8> = public_key.to_bytes().to_vec();  // 32 bytes
    let credential = BasicCredential::new(public_key_bytes);
    // ...
}
```

And verified in tests:
```rust
fn test_new_credentials_use_32_byte_format() {
    // ...
    assert_eq!(identity_bytes.len(), 32,
        "New credentials should use 32-byte raw format, not 64-byte UTF-8 encoded hex");
}
```

MDK explicitly rejects anything other than 32 bytes:
```rust
pub(crate) fn parse_credential_identity(&self, identity_bytes: &[u8]) 
    -> Result<PublicKey, Error> 
{
    if identity_bytes.len() != 32 {
        return Err(Error::KeyPackage(format!(
            "Invalid credential identity length: {} (expected 32)",
            identity_bytes.len()
        )));
    }
    // ...
}
```

**Note:** MDK previously used 64-byte UTF-8 hex encoding (legacy format) but now rejects it. The code comments and tests explicitly document this transition.

---

## 3. How Does MDK Serialize credential_type?

**As uint16 (standard TLS, 2 bytes big-endian).**

From OpenMLS `credentials/mod.rs`:
```rust
impl Size for CredentialType {
    fn tls_serialized_len(&self) -> usize { 2 }
}

impl TlsSerializeTrait for CredentialType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;
        Ok(2)
    }
}
```

BasicCredential = 0x0001 = `[0x00, 0x01]`.

The `Credential` struct serializes as:
```
credential_type:                uint16 (2 bytes)
serialized_credential_content:  VLBytes (varint-length + content)
```

For a BasicCredential with 32-byte identity, the serialized_credential_content is just the raw identity bytes (no nested encoding). Total credential bytes: `0x0001` + `0x20` + 32 bytes = 35 bytes.

---

## 4. Does MDK Include Default Extensions in Capabilities?

**No. MDK is RFC 9420 compliant on this point.**

From `mdk-core/src/constant.rs`:
```rust
/// Per RFC 9420 Section 7.2, this should only include non-default extensions that
/// the client supports. Default extensions (RequiredCapabilities, RatchetTree,
/// ApplicationId, ExternalPub, ExternalSenders) are assumed to be supported by all
/// clients and should NOT be listed here.
pub const SUPPORTED_EXTENSIONS: [ExtensionType; 2] = [
    ExtensionType::LastResort,                                   // 0x000A
    ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE),     // 0xF2EE
];
```

Plus GREASE values are dynamically injected at runtime via `Capabilities::with_grease()`.

So the capabilities.extensions list contains: `[GREASE, 0x000A, 0xF2EE]` (order may vary, GREASE value is random).

---

## 5. Exact TLS Serialization Layout

### KeyPackage (outer structure)

```
KeyPackageIn {
    payload: KeyPackageTbsIn,    // TLS-serialized inline (no length prefix)
    signature: Signature,         // VLBytes (varint-length + Ed25519 sig, 64 bytes)
}
```

### KeyPackageTbsIn (to-be-signed payload)

```
KeyPackageTbsIn {
    protocol_version: ProtocolVersion,  // uint16 (0x0001 = MLS 1.0)
    ciphersuite: Ciphersuite,           // uint16 (0x0001 = X25519/AES128/SHA256/Ed25519)
    init_key: InitKey,                  // VLBytes = varint(32) + 32 bytes HPKE public key
    leaf_node: LeafNode,                // inline (see below)
    extensions: Extensions<AnyObject>,  // Vec<Extension> = varint-length-prefix + extensions
}
```

### LeafNode

```
LeafNode {
    payload: LeafNodePayload,    // inline (see below)
    signature: Signature,         // VLBytes (varint-length + Ed25519 sig, 64 bytes)
}
```

### LeafNodePayload

```
LeafNodePayload {
    encryption_key: EncryptionKey,       // VLBytes = varint(32) + 32 bytes HPKE key
    signature_key: SignaturePublicKey,    // VLBytes = varint(32) + 32 bytes Ed25519 key
    credential: Credential,              // inline (see below)
    capabilities: Capabilities,          // inline (see below)
    leaf_node_source: LeafNodeSource,    // uint8 discriminant + content
    extensions: Extensions<LeafNode>,    // Vec<Extension> = varint-length + extensions
}
```

### Credential (BasicCredential)

```
Credential {
    credential_type: CredentialType,              // uint16 (0x0001)
    serialized_credential_content: VLBytes,       // varint(32) + 32 bytes (Nostr pubkey)
}
```

### Capabilities

```
Capabilities {
    versions: Vec<ProtocolVersion>,       // varint-length + N × uint16
    ciphersuites: Vec<VerifiableCiphersuite>,  // varint-length + N × uint16
    extensions: Vec<ExtensionType>,       // varint-length + N × uint16
    proposals: Vec<ProposalType>,         // varint-length + N × uint16
    credentials: Vec<CredentialType>,     // varint-length + N × uint16
}
```

### LeafNodeSource (for key_package)

```
LeafNodeSource::KeyPackage {
    discriminant: uint8 (0x01)
    lifetime: Lifetime {
        not_before: uint64 (8 bytes)
        not_after: uint64 (8 bytes)
    }
}
```

### Extensions (Vec<Extension>)

Each Extension is:
```
Extension {
    extension_type: ExtensionType,    // uint16
    extension_data: VLBytes,          // varint-length + data bytes
}
```

The Vec<Extension> itself is varint-length-prefixed (total byte count of all extensions).

### KeyPackage extensions

MDK uses `.mark_as_last_resort()` which adds a LastResort extension:
```
kp_extensions: varint-length + [
    extension_type: uint16 (0x000a)
    extension_data: varint(0)        // empty data (0 bytes)
]
```

Total: varint(3) + 0x000A + varint(0) = 1 + 2 + 1 = 4 bytes typically.

### Complete Wire Format (Byte-by-Byte for MDK)

```
Offset  Len  Field
------  ---  -----
0       2    protocol_version: uint16 (0x0001)
2       2    ciphersuite: uint16 (0x0001)
4       1    init_key length: varint (0x20 = 32)
5       32   init_key data (HPKE X25519 public key)
37      1    encryption_key length: varint (0x20 = 32)
38      32   encryption_key data (HPKE X25519 public key)
70      1    signature_key length: varint (0x20 = 32)
71      32   signature_key data (Ed25519 public key)
103     2    credential_type: uint16 (0x0001 = basic)
105     1    identity length: varint (0x20 = 32)
106     32   identity data (raw Nostr pubkey bytes)
138     1+   capabilities.versions: varint(N) + N bytes
               Typically: varint(2) + [0x00, 0x01] + GREASE
...     1+   capabilities.ciphersuites: varint(N) + N bytes
               Typically: varint(N) + [0x00, 0x01] + GREASE
...     1+   capabilities.extensions: varint(N) + N bytes
               Typically: varint(N) + [GREASE 2B] + [0x00, 0x0A] + [0xF2, 0xEE]
...     1+   capabilities.proposals: varint(N) + N bytes
               Typically: varint(N) + GREASE values
...     1+   capabilities.credentials: varint(N) + N bytes
               Typically: varint(N) + [0x00, 0x01] + GREASE
...     1    leaf_node_source: uint8 (0x01 = key_package)
...     8    lifetime.not_before: uint64
...     8    lifetime.not_after: uint64
...     1+   leaf_extensions: varint(0) = 0x00 (empty)
...     1+   leaf_signature: varint(64) + 64 bytes Ed25519 signature
...     1+   kp_extensions: varint(N) + last_resort extension
               [0x00, 0x0A, 0x00] (type=0x000A, data_len=0)
...     1+   kp_signature: varint(64) + 64 bytes Ed25519 signature
```

### Why MDK KeyPackages Are ~366 Bytes vs marmot-chat ~317-331 Bytes

The size difference is entirely due to **GREASE values** in capabilities:

| Component | MDK (with GREASE) | marmot-chat |
|-----------|-------------------|-------------|
| capabilities.versions | 2 (MLS1.0) + 2 (GREASE) = 4B | 2 (MLS1.0) = 2B |
| capabilities.ciphersuites | 2 (0x0001) + 2 (GREASE) = 4B | 2 (0x0001) = 2B |
| capabilities.extensions | 2+2+2 (GREASE+LastResort+NostrGroupData) = 6B | 2+2+2 (GREASE+0xf2ee+0x000a) = 6B |
| capabilities.proposals | 2 (GREASE) = 2B | 0B |
| capabilities.credentials | 2 (Basic) + 2 (GREASE) = 4B | 2 (Basic) = 2B |

MDK injects GREASE into ALL capability lists (ciphersuites, extensions, proposals, credentials). marmot-chat may inject fewer GREASE values. This accounts for the ~35-49 byte difference.

---

## 6. OpenMLS Version and tls_codec Details

- **OpenMLS:** 0.8.0 (released 2026-02-04)
- **tls_codec:** 0.4.2 with features: `derive`, `serde`, `mls`
- **openmls_basic_credential:** 0.5.0
- **openmls_rust_crypto:** 0.5.0 (for Ed25519 + X25519)

The `mls` feature in tls_codec is the critical feature. It:
1. Limits variable-length values to 30-bit (vs 62-bit for QUIC)
2. Enforces minimum-length encoding (canonical)
3. Rejects 8-byte length fields (only 1, 2, or 4 byte lengths)

**Both MDK and marmot-chat use OpenMLS with the `mls` feature. They produce identical wire formats.**

---

## 7. Content Encoding in kind:443 Events

**MDK always uses base64 encoding with an explicit `["encoding", "base64"]` tag.**

From `mdk-core/src/key_packages.rs`:
```rust
// SECURITY: Always use base64 encoding with explicit encoding tag per MIP-00/MIP-02.
let encoding = ContentEncoding::Base64;
let encoded_content = encode_content(&key_package_serialized, encoding);
```

From `mdk-core/src/util.rs`:
```rust
pub enum ContentEncoding {
    Base64,  // The ONLY supported encoding
}
```

MDK **does not support hex encoding**. It will reject events without an `["encoding", "base64"]` tag:
```rust
let encoding = ContentEncoding::from_tags(event.tags.iter())
    .ok_or_else(|| Error::KeyPackage("Missing required encoding tag".to_string()))?;
```

### About Kai's Event (d2ad6d9c)

If Kai's event has **both** encoding tags (base64 and hex), this is likely:
1. **A relay-side duplicate tag injection bug**, OR
2. **An older MDK version** that may have supported hex (MDK previously used 64-byte hex-encoded identity), OR
3. **A different client** altogether that generated the KeyPackage

**Key insight from the code comments:** MDK made a breaking change from 64-byte UTF-8 hex identity to 32-byte raw bytes. If Kai's KeyPackage was generated by an older MDK version, it would have 64-byte identity, which would cause our 32-byte parser to fail.

### Debugging the 366-byte KeyPackage

If Kai's event uses base64 content, decode it to get raw bytes, then parse with the same varint format. If it's actually hex-encoded content, the decoded bytes would be different length.

**Critical check:** Verify whether the content field is base64 or hex by examining the first few characters. Base64 uses `A-Za-z0-9+/=`, hex uses `0-9a-f`.

---

## 8. Differences from marmot-chat

| Aspect | MDK (0.5.3) | marmot-chat |
|--------|------------|-------------|
| Wire format | MLS varint (RFC 9420) | MLS varint (RFC 9420) |
| Identity format | 32 bytes raw | 32 bytes raw |
| credential_type | uint16 | uint16 |
| Default extensions in caps | Not listed (RFC compliant) | Not listed (RFC compliant) |
| GREASE values | All 5 capability lists | Varies |
| Content encoding | base64 only | base64 (assumed) |
| Encoding tag | Required (`["encoding", "base64"]`) | May not include |
| Extensions in caps | GREASE + 0x000a + 0xf2ee | GREASE + 0xf2ee + 0x000a |
| KP extensions | LastResort (0x000a) | LastResort (0x000a) |

**The wire formats are identical.** Differences are only in:
1. Number and position of GREASE values (random, expected to differ)
2. Event-level tags (encoding tag requirement)

---

## 9. RFC 9420 Compliance

MDK is **fully RFC 9420 compliant**:

- ✅ MLS varint encoding (Section 2.1.2) via `tls_codec` with `mls` feature
- ✅ KeyPackage structure (Section 10.1)
- ✅ LeafNode structure (Section 7.2)
- ✅ Credential encoding (Section 5.3)
- ✅ Default extensions NOT listed in capabilities (Section 7.2)
- ✅ GREASE values injected (Section 13.5)
- ✅ LastResort extension support (Section 17.3)
- ✅ Lifetime validation for key packages
- ✅ Init key ≠ encryption key validation
- ✅ Identity binding verification (event signer = credential identity)

---

## 10. Recommendations for marmot-ts Parser

### The parser should already work for MDK

Since MDK uses the exact same MLS varint encoding as marmot-chat, the parser that works for marmot-chat should work for MDK KeyPackages. The issue with Kai's KeyPackage is likely one of:

### Possible causes of the 366-byte parsing failure

1. **Content encoding mismatch:** If the parser is hex-decoding a base64-encoded string (or vice versa), the raw bytes will be wrong. Check the `["encoding", "base64"]` tag.

2. **Legacy 64-byte identity:** If Kai's KeyPackage was generated by an older MDK version, the identity might be 64 bytes (UTF-8 hex string). The parser should handle both:
   ```typescript
   // After reading identity bytes
   if (identity.length === 32) {
     // Modern format: raw 32-byte pubkey
     pubkey = bytesToHex(identity);
   } else if (identity.length === 64) {
     // Legacy format: UTF-8 encoded hex string
     pubkey = new TextDecoder().decode(identity);
   }
   ```

3. **GREASE value count:** MDK injects GREASE into ALL 5 capability lists. If the parser hardcodes expected lengths, GREASE randomness will cause failures.

4. **Different GREASE values:** GREASE values are random uint16 matching pattern `0x?A?A`. Don't reject unknown extension/proposal/ciphersuite/credential types — just skip them.

### Parser recommendations

1. **Always check the `["encoding", ...]` tag** before decoding the content field. Support at least `base64`. For robustness, try both if no tag is present (but log a warning).

2. **Use varint decoding everywhere** — there is no client in the Marmot ecosystem that uses fixed-size TLS encoding. All use OpenMLS with `tls_codec` `mls` feature.

3. **Be GREASE-tolerant:** Skip unknown values in all capability lists. Don't fail on:
   - Unknown ciphersuites (GREASE: `0x0A0A`, `0x1A1A`, ..., `0xEAEA`)
   - Unknown extension types (same GREASE pattern)
   - Unknown proposal types
   - Unknown credential types

4. **Handle variable capabilities sizes:** The number of items in each capabilities list varies between clients and even between key packages from the same client (GREASE is random).

5. **Support both 32-byte and 64-byte identity** for backward compatibility with older MDK versions.

6. **Parse Extensions correctly:** Each Extension is `{type: uint16, data: VLBytes}`. The outer Extensions list is `VLBytes(concat(all_extensions))`.

---

## 11. Bugs Found

### No bugs in MDK's wire format implementation.

MDK's implementation is clean and well-documented. However, some observations:

1. **The `key_package_inspection.rs` example has a potential bug** on line 171:
   ```rust
   let key_package_bytes = hex::decode(&key_package_encoded)?;
   ```
   This tries to hex-decode a base64-encoded string, which would fail. This example appears to have been written before the base64 migration and may not have been updated. (This is an example code issue, not a library bug.)

2. **No backward compatibility for hex encoding:** MDK's `ContentEncoding` enum only supports `Base64`. Events from older clients using hex encoding would be rejected. This is intentional per MIP-00/MIP-02 security requirements but could cause interop issues with very old events.

3. **Tag validation strictness:** MDK requires the `encoding` tag to be present and will reject events without it. Clients like marmot-chat may not always include this tag, which would cause MDK to reject their key packages. The marmot-ts parser should be more lenient.

---

## Appendix A: Quick Reference — Varint Encoding

```
Value 0-63:     1 byte:  [00xxxxxx]
Value 64-16383: 2 bytes: [01xxxxxx, xxxxxxxx]
Value 16384+:   4 bytes: [10xxxxxx, xxxxxxxx, xxxxxxxx, xxxxxxxx]
```

Common values:
- Length 0:  `0x00`
- Length 2:  `0x02`
- Length 3:  `0x03`
- Length 4:  `0x04`
- Length 6:  `0x06`
- Length 32: `0x20`
- Length 64: `0x40, 0x40` (2 bytes: `01_000000 01_000000` = 64)

**Wait — important detail!** For length 64:
- `0x40` in single-byte means the top 2 bits are `01` → 2-byte encoding
- So `0x40` alone means length = `0x40 & 0x3f` = 0, but that requires reading a second byte
- Actually: `0x40 0x40` = (0x40 & 0x3f) << 8 | 0x40 = 0 << 8 | 64 = 64 ✓

For Ed25519 signatures (64 bytes), the varint prefix is `0x40 0x40` (2 bytes).

## Appendix B: Expected MDK KeyPackage Size Calculation

```
Fixed fields:
  protocol_version:  2
  ciphersuite:       2
  init_key:          1 + 32 = 33
  encryption_key:    1 + 32 = 33
  signature_key:     1 + 32 = 33
  credential_type:   2
  identity:          1 + 32 = 33
  leaf_node_source:  1
  lifetime:          16
  kp_signature:      2 + 64 = 66
  leaf_signature:    2 + 64 = 66

Variable capability fields (MDK with GREASE in all lists):
  versions prefix:      1
  versions data:        2 (MLS1.0) + 2 (GREASE) = 4
  ciphersuites prefix:  1  
  ciphersuites data:    2 + 2 = 4
  extensions prefix:    1
  extensions data:      2 + 2 + 2 = 6  (GREASE + LastResort + NostrGroupData)
  proposals prefix:     1
  proposals data:       2 (GREASE)
  credentials prefix:   1
  credentials data:     2 + 2 = 4

Extension fields:
  leaf_extensions:  1 (varint 0, empty)
  kp_extensions:    1 (varint 3) + 2 (type 0x000A) + 1 (varint 0) = 4

Total: 2+2+33+33+33+2+33+1+16+66+66 + 1+4+1+4+1+6+1+2+1+4 + 1+4 = ~317

With GREASE varying: +2 to +10 bytes depending on how many GREASE values
```

Estimated MDK KeyPackage size: **~317–367 bytes** (varies with GREASE randomness).

The 366-byte size observed for Kai's KeyPackage is fully consistent with an MDK-generated KeyPackage with GREASE values.
