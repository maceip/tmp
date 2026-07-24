# Security Audit Report: TLSNotary TLS Client & Cryptographic Implementation

**Date:** 2026-07-24
**Scope:** TLS client state machine, backends, crypto operations, proof verification, session types
**Exclusions:** Previously reported findings (EMS not applied, OCSP stapling ignored, debug `println!` with key material, prover doesn't verify notary signature, unsigned `server_name` in `SessionProof`)

---

## Finding 1: Decryption Failure Causes Panic (Denial of Service)

**Severity:** High
**File:** `crates/tls/client/src/crypto/standard.rs`, lines 655-660
**Category:** Implementation Bug / Denial of Service

### Description

The `StandardCrypto::Decrypter::decrypt_aes128gcm` method calls `.unwrap()` on the AES-GCM decryption result. If a malicious server or network attacker sends a corrupted ciphertext that fails AEAD authentication, this causes an unrecoverable panic, crashing the entire process.

### Evidence

```
655|        let cipher = Aes128Gcm::new_from_slice(&self.write_key).unwrap();
...
660|        let plaintext = cipher.decrypt(nonce, aes_payload).unwrap();
```

In contrast, the `RustCryptoBackend` version in `crates/tls/client/src/backend/standard.rs` (line 534-536) correctly propagates the error:
```
534|        let plaintext = cipher
535|            .decrypt(nonce, aes_payload)
536|            .map_err(|e| BackendError::DecryptionError(e.to_string()))?;
```

### Attack Chain

1. Attacker performs a network-level MITM or the TLS server sends malformed encrypted data.
2. The corrupted ciphertext arrives at the client.
3. `decrypt_aes128gcm` is called, AES-GCM authentication fails.
4. `.unwrap()` is called on the `Err` result.
5. The process panics and terminates.

This is also present in the encryption path at line 602:
```
602|        let ciphertext = cipher.encrypt(nonce, payload).unwrap();
```

### Impact

Any network attacker can crash a TLSNotary prover process by injecting a single corrupted TLS record. No authentication is required since the corruption happens at the record layer before handshake completion is verified.

---

## Finding 2: Extended Master Secret (EMS) Extension Not Sent

**Severity:** High
**File:** `crates/tls/client/src/client/hs.rs`, line 218
**Category:** Protocol Downgrade / Missing Security Feature

### Description

The `ClientExtension::ExtendedMasterSecretRequest` extension is commented out in the ClientHello construction, meaning the client never requests EMS from the server. This is separate from the known "EMS negotiated but not applied" issue — here, EMS is never even *requested*.

### Evidence

```
218|        //ClientExtension::ExtendedMasterSecretRequest,
```

The `using_ems` field is initialized to `false` in `start_handshake` (line 148 of the `ExpectServerHello` struct shows `using_ems: self.using_ems`), and it can only become `true` if the server acks it (line 80 of `tls12.rs`: `self.using_ems = server_hello.ems_support_acked()`). But since the client never sends the extension, a well-behaved server will never ack it.

### Attack Chain

1. Client connects to a TLS 1.2 server without requesting EMS.
2. The TLS 1.2 session is established without Extended Master Secret protection.
3. An attacker who can observe the handshake can perform a Triple Handshake attack (CVE-2014-6593 class), potentially binding a client's session to a different server context.
4. This is especially dangerous in the TLSNotary context where the master secret is derived via MPC — without EMS, the master secret derivation does not incorporate the full handshake transcript, making it possible to confuse session bindings.

### Impact

Without EMS, TLS 1.2 connections are vulnerable to the well-known Triple Handshake attack. In the TLSNotary protocol, this could allow a malicious server to trick the prover into creating notarized proofs that are bound to a different session than intended.

---

## Finding 3: MPC Backend Ignores `set_hs_hash_client_key_exchange` (EMS Seed Discarded)

**Severity:** High
**File:** `crates/tls/mpc/src/leader.rs`, lines 517-519
**Category:** Missing Validation / Protocol Implementation Gap

### Description

The MPC backend's implementation of `set_hs_hash_client_key_exchange` is a no-op — it silently discards the handshake hash that would be used as the EMS seed. Even if EMS were negotiated and the extension were sent, the MPC backend would never use it.

### Evidence

```
517|    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
518|        Ok(())
519|    }
```

Compare with the `RustCryptoBackend` in `crates/tls/client/src/backend/standard.rs` lines 313-316, which stores it:
```
313|    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
314|        self.ems_seed = Some(hash.to_vec());
315|        Ok(())
316|    }
```

Similarly, `set_hs_hash_server_hello` in the MPC backend (lines 521-523) is also a no-op.

### Attack Chain

1. Even if the EMS extension request were un-commented, the MPC backend would not incorporate the handshake hash into the master secret derivation.
2. The PRF-based master secret derivation in the MPC path would use only `client_random || server_random` as seed, not the full handshake hash.
3. This silently downgrades security to non-EMS behavior even if both client and server believe EMS is active.

### Impact

The MPC backend has a structural inability to support EMS. This compounds with Finding 2 to make TLS 1.2 connections via the MPC path inherently vulnerable to Triple Handshake attacks.

---

## Finding 4: `SessionHeader.verify()` Does Not Validate `sent_len` / `recv_len`

**Severity:** Medium
**File:** `crates/core/src/session/header.rs`, lines 59-80
**Category:** Incomplete Verification / Proof Forgery

### Description

The `SessionHeader::verify()` method validates `time`, `merkle_root`, `encoder_seed`, `handshake_data`, and `server_public_key`, but does not validate the `sent_len` and `recv_len` fields against any externally supplied values.

### Evidence

```
59|    pub fn verify(
60|        &self,
61|        time: u64,
62|        server_public_key: &PublicKey,
63|        root: &MerkleRoot,
64|        encoder_seed: &[u8; 32],
65|        handshake_data_decommitment: &Decommitment<HandshakeData>,
66|    ) -> Result<(), SessionHeaderVerifyError> {
67|        let ok_time = self.handshake_summary.time().abs_diff(time) <= 300;
68|        let ok_root = &self.merkle_root == root;
69|        let ok_encoder_seed = &self.encoder_seed == encoder_seed;
70|        let ok_handshake_data = handshake_data_decommitment
71|            .verify(self.handshake_summary.handshake_commitment())
72|            .is_ok();
73|        let ok_server_public_key = self.handshake_summary.server_public_key() == server_public_key;
74|
75|        if !(ok_time && ok_root && ok_encoder_seed && ok_handshake_data && ok_server_public_key) {
76|            return Err(SessionHeaderVerifyError::InconsistentHeader);
77|        }
78|
79|        Ok(())
80|    }
```

The `sent_len` and `recv_len` fields are part of the `SessionHeader` that gets signed by the Notary, and they are used by `SubstringsProof::verify()` (in `substrings.rs`, line 264) to bound-check proof ranges. However, the Prover's own `verify()` call does not check these against the actual transcript lengths.

### Attack Chain

1. A malicious Notary provides a `SessionHeader` with inflated `sent_len` or `recv_len`.
2. The Prover calls `verify()`, which succeeds because it doesn't check these lengths.
3. The `SubstringsProof::verify()` later uses these inflated lengths as bounds, potentially allowing proofs to reference out-of-bounds ranges.
4. The verification buffers are allocated based on these lengths (`let mut sent = vec![0u8; header.sent_len()];`), so a malicious Notary could also cause excessive memory allocation.

### Impact

A malicious Notary could manipulate transcript length fields in the signed header, affecting downstream proof verification bounds and enabling memory exhaustion attacks.

---

## Finding 5: Time Verification Uses Overly Broad 300-Second Window

**Severity:** Medium
**File:** `crates/core/src/session/header.rs`, line 67
**Category:** Weak Validation

### Description

The `SessionHeader::verify()` method allows a 300-second (5-minute) window for time validation. This means the Notary can backdate or postdate the session timestamp by up to 5 minutes.

### Evidence

```
67|        let ok_time = self.handshake_summary.time().abs_diff(time) <= 300;
```

### Attack Chain

1. A malicious Notary sets the session time to be 5 minutes in the future.
2. The Prover verifies the header — the time check passes.
3. The certificate chain is verified against the session time via `SessionInfo::verify()` in `proof/session.rs` line 122-126:
   ```
   UNIX_EPOCH + Duration::from_secs(handshake_summary.time())
   ```
4. With a 5-minute window, an attacker could potentially:
   - Use a certificate that has just expired (by shifting time backwards).
   - Use a certificate that hasn't yet become valid (by shifting time forwards).
   - Create notarized proofs that appear to have occurred at a different time, undermining audit trails.

### Impact

The 5-minute tolerance could allow use of recently-expired or not-yet-valid certificates, and enables timestamp manipulation in notarized sessions.

---

## Finding 6: `HandshakeData::verify()` Discards Verification Results

**Severity:** Medium
**File:** `crates/tls/core/src/handshake.rs`, lines 72 and 94
**Category:** Incorrect Error Handling

### Description

The `HandshakeData::verify()` method uses `_ = verifier.verify_server_cert(...)` and `_ = verifier.verify_tls12_signature(...)`, explicitly discarding the `ServerCertVerified` and `HandshakeSignatureValid` marker types. While the `?` operator does propagate errors, the discarded return values are intended as compile-time proof that verification occurred (the "goto fail" pattern defense from `tls_core::verify`).

### Evidence

```
72|        _ = verifier.verify_server_cert(
73|            end_entity,
74|            intermediates,
75|            server_name,
...
84|            time,
85|        )?;
...
94|        _ = verifier.verify_tls12_signature(
95|            &message,
96|            &self.server_cert_details().cert_chain()[0],
97|            sig,
98|        )?;
```

### Attack Chain

This is a design weakness rather than a directly exploitable bug. The marker types (`ServerCertVerified`, `HandshakeSignatureValid`) are designed to be carried through the control flow to prove verification happened, as documented in `verify.rs` lines 34-41. Discarding them means a future refactor could accidentally remove the `?` error propagation without a compile error, silently skipping verification.

Additionally, the `assertion()` constructors on these types are `pub`, meaning any code can create these markers without performing actual verification (as is done in `tls13.rs` line 336-337 for session resumption).

### Impact

Reduced defense-in-depth against accidental verification bypasses in future code changes. The public `assertion()` constructors also mean these marker types don't provide the compile-time guarantees they claim to.

---

## Finding 7: `SubstringsProof::verify()` Does Not Validate Commitment Direction Consistency

**Severity:** Medium
**File:** `crates/core/src/proof/substrings.rs`, lines 221-300
**Category:** Incomplete Verification

### Description

In `SubstringsProof::verify()`, the commitment `CommitmentInfo` includes a `direction` field that indicates whether data is from the sent or received transcript. However, the verification loop does not cross-check that the `direction` in the opening matches the `direction` that was originally committed to in the Merkle tree. The direction is part of the `CommitmentInfo` which is provided alongside the opening, but both come from the untrusted prover.

### Evidence

The `CommitmentInfo` containing `direction` is deserialized from the proof:
```
221|        for (id, (info, opening)) in openings {
222|            let CommitmentInfo {
223|                ranges, direction, ..
224|            } = info;
```

The direction determines which transcript buffer receives the data and which encoding IDs are generated:
```
269|            let encodings = get_value_ids(&ranges, direction)
270|                .map(|id| {
271|                    header
272|                        .encoder()
273|                        .encode_by_type(EncodingId::new(&id).to_inner(), &ValueType::U8)
274|                })
275|                .collect::<Vec<_>>();
```

If the encoding IDs for sent vs received data happen to produce different values (which they should by design of `get_value_ids`), this provides *implicit* protection. However, if the encoding scheme doesn't strongly separate sent vs received IDs, a prover could claim received data as sent data or vice versa.

### Attack Chain

1. A malicious prover constructs a `SubstringsProof` with a `CommitmentInfo` that claims data from the "Sent" direction actually came from "Received" or vice versa.
2. If encoding IDs for sent/received don't have domain separation, the Merkle proof could still validate.
3. The verifier would then place received data into the sent transcript or vice versa.

### Impact

Could allow a prover to swap data between sent and received transcripts in the proof, potentially misattributing who said what in the TLS conversation.

---

## Finding 8: Nonce Reuse Risk in StandardCrypto Encryption

**Severity:** Medium
**File:** `crates/tls/client/src/crypto/standard.rs`, lines 494-511
**Category:** Cryptographic Weakness

### Description

The `StandardCrypto` encryption path uses a hardcoded explicit nonce `[0, 0, 0, 0, 0, 0, 0, 1]` for the `ClientFinished` handshake message (line 501). While the comment explains this is intentional for GC round-trip optimization, any other handshake message that happens to be encrypted (due to a state machine bug or protocol extension) would also use this same nonce, creating a nonce reuse vulnerability.

### Evidence

```
494|                        match m.typ {
495|                            ContentType::Handshake => {
496|                                // In TLS 1.2 the only handshake message that needs to be
497|                                // encrypted by the client is Client_Finished.
498|
499|                                // By fixing the explicit_nonce of Client_Finished, we
500|                                // can save a round-trip in GC
501|                                explicit_nonce = [0, 0, 0, 0, 0, 0, 0, 1];
502|                            }
503|                            ContentType::ApplicationData => {
504|                                explicit_nonce = thread_rng().gen();
505|                            }
```

Additionally, for `ApplicationData`, the nonce is generated via `thread_rng().gen()`, which produces random 8-byte nonces. While the collision probability for random nonces is low for a single session, AES-GCM's security guarantees degrade after ~2^32 encryptions with random nonces due to the birthday bound. The `RustCryptoBackend` in `backend/standard.rs` line 370 uses the sequence number instead (`&seq.to_be_bytes()`), which is the correct approach for TLS 1.2.

### Attack Chain

1. If a state machine bug causes multiple handshake messages to be encrypted, they all use the same fixed nonce `[0,0,0,0,0,0,0,1]`.
2. With the same key and nonce, AES-GCM's keystream is identical, allowing XOR of ciphertexts to reveal the XOR of plaintexts.
3. For ApplicationData, the random nonce approach is less dangerous but deviates from the TLS 1.2 specification which mandates unique explicit nonces per record.

### Impact

Nonce reuse under AES-GCM completely breaks confidentiality and can reveal authentication keys. The fixed handshake nonce is safe only if exactly one handshake message is ever encrypted, which relies on correct state machine behavior.

---

## Summary Table

| # | Finding | Severity | File | Lines |
|---|---------|----------|------|-------|
| 1 | Decryption panic on auth failure | High | `crypto/standard.rs` | 660 |
| 2 | EMS extension never sent | High | `client/hs.rs` | 218 |
| 3 | MPC backend discards EMS seed | High | `mpc/leader.rs` | 517-519 |
| 4 | `sent_len`/`recv_len` not verified | Medium | `session/header.rs` | 59-80 |
| 5 | 300-second time validation window | Medium | `session/header.rs` | 67 |
| 6 | Verification results discarded | Medium | `core/handshake.rs` | 72, 94 |
| 7 | Commitment direction not cross-validated | Medium | `proof/substrings.rs` | 221-300 |
| 8 | Nonce reuse risk in StandardCrypto | Medium | `crypto/standard.rs` | 494-511 |
