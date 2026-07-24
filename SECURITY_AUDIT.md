# Security Audit: TLSNotary MPC Protocol Implementation

**Date:** 2026-07-24
**Scope:** MPC-TLS protocol implementation including leader/follower, stream cipher, AEAD, key exchange, and common infrastructure.
**Excluded:** Findings already documented (bincode deserialization limits, integer overflow in `check_transcript_length`, follower transcript size bypass, record layer payload length validation, non-constant-time GCM tag comparison, ECDH point decomposition panic, verifier ProvingInfo panic, EMS key derivation, debug println with key material).

---

## Finding 1: AEAD Decrypt Payload Arithmetic Underflow (Panic / DoS)

**Severity:** High
**File:** `crates/components/aead/src/aes_gcm/mod.rs`
**Lines:** 215-218, 248-251, 281-284, 313-316, 341-344, 386-389

### Description

All decrypt and verify methods in `MpcAesGcm` compute `payload.len() - TAG_LEN` before checking whether the payload is long enough. When `payload.len() < 16`, this arithmetic underflows: in debug mode it panics immediately; in release mode the wrapping subtraction produces `usize::MAX - (15 - payload.len())`, and the subsequent `Vec::split_off` call panics because the index exceeds the vector length.

### Affected Code

```rust
// aes_gcm/mod.rs – decrypt_public (line 215), identical pattern in 5 other methods
let purported_tag: [u8; TAG_LEN] = payload
    .split_off(payload.len() - TAG_LEN)   // <-- underflow if payload.len() < 16
    .try_into()
    .map_err(|_| AesGcmError::payload("payload is not long enough to contain tag"))?;
```

The `.map_err` branch is unreachable because the panic occurs before the `try_into()`.

### Attack Chain

1. A malicious MPC leader constructs a `DecryptServerFinished`, `DecryptAlert`, or `CommitMessage` containing fewer than 16 bytes of ciphertext payload.
2. The follower deserializes the message and passes the short payload to `MpcAesGcm::decrypt_public` (or `decrypt_blind`, `verify_tag`, `verify_plaintext`).
3. `payload.len() - TAG_LEN` underflows, causing a panic.
4. The follower process crashes, denying service.

### Evidence

- `decrypt_public` at line 215: `payload.split_off(payload.len() - TAG_LEN)`
- `decrypt_private` at line 248: same pattern
- `decrypt_blind` at line 281: same pattern
- `verify_tag` at line 313: same pattern
- `prove_plaintext` at line 341: same pattern
- `verify_plaintext` at line 386: same pattern

No length guard precedes any of these six call sites. While the known "record layer payload length validation" finding addresses a similar issue in `record_layer.rs`, this finding is in the AEAD component itself, which has an independent interface and could be used outside the record layer. The AEAD should defensively validate its own inputs.

### Recommendation

Add an early length check:
```rust
if payload.len() < TAG_LEN {
    return Err(AesGcmError::payload("payload is not long enough to contain tag"));
}
```

---

## Finding 2: AES-CTR Counter Truncation via Silent `as u32` Cast

**Severity:** Medium
**File:** `crates/components/stream-cipher/src/keystream.rs`
**Line:** 172

### Description

The AES-CTR counter value is computed as `(start_ctr + i) as u32`, where both `start_ctr` and `i` are `usize` (64-bit on common platforms). If the sum exceeds `u32::MAX`, the cast silently truncates the upper bits. This causes counter-block reuse within the same nonce, which is catastrophic for CTR-mode ciphers: XOR-ing two keystream blocks derived from the same counter yields the XOR of the two plaintexts.

### Affected Code

```rust
// keystream.rs line 172
thread.assign(ctr_ref, ((start_ctr + i) as u32).to_be_bytes())?;
```

`start_ctr` comes from `StreamCipherConfig.start_ctr` which is `usize` with no upper-bound validation, and `i` is the block index within a message.

### Attack Chain

1. An attacker who controls configuration (e.g., through config injection or a modified build) sets `start_ctr` to a value near `u32::MAX` (e.g., `0xFFFF_FFFE`).
2. When encrypting a multi-block message, `start_ctr + i` wraps past `u32::MAX`.
3. The `as u32` cast truncates, producing counter values that collide with earlier blocks.
4. Two AES-CTR blocks share the same counter, yielding the same keystream.
5. XOR of the two resulting ciphertext blocks reveals the XOR of the corresponding plaintexts.

### Evidence

- `start_ctr` is `usize` (line 11 of `config.rs`) with no maximum bound validation.
- The `as u32` cast on line 172 of `keystream.rs` performs silent truncation.
- No overflow check (`checked_add`, `u32::try_from`) is performed.

### Recommendation

Use `u32::try_from(start_ctr + i)` and return an error on overflow rather than silently truncating.

---

## Finding 3: Follower `encrypt_alert` Missing Active-State Validation

**Severity:** Medium
**File:** `crates/tls/mpc/src/follower.rs`
**Lines:** 386–412

### Description

The follower's `encrypt_alert` method checks `is_accepting_messages()` (which validates `close_notify` and `committed` flags) but does **not** check that the state machine is in the `Active` state. Compare with `encrypt_message` (line 418) which calls both `is_accepting_messages()` and `self.state.try_as_active()`.

Because the encrypter is started during `compute_key_exchange` (before the `Active` state is reached), a malicious leader can send an `EncryptAlert` message while the follower is still in the `Sf` state (between `EncryptClientFinished` and `ServerFinishedVd`).

### Affected Code

```rust
// follower.rs line 386-412
async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
    self.is_accepting_messages()?;
    // Missing: self.state.try_as_active()?;
    if let Some(alert) = AlertMessagePayload::read_bytes(&msg) {
        ...
    }
    self.encrypter.encrypt_public(...).await?;
    Ok(())
}
```

### Attack Chain

1. Leader sends `ComputeKeyExchange` → follower enters `Ke` state, encrypter starts.
2. Leader sends `ClientFinishedVd` → follower enters `Cf` state.
3. Leader sends `EncryptClientFinished` → follower enters `Sf` state.
4. **Leader sends `EncryptAlert` (CloseNotify) before completing the handshake.**
5. Follower encrypts the alert (encrypter is already started), advancing the encrypt sequence number.
6. The TLS server receives a CloseNotify before the handshake completes, causing an abort.
7. Subsequent encrypt operations between leader and follower may have desynchronized sequence numbers if the leader does not also encrypt the alert.

### Evidence

- `encrypt_message` (line 418) calls `self.state.try_as_active()?` — this check is present.
- `encrypt_alert` (line 386) does NOT call `self.state.try_as_active()?` — missing.
- The encrypter is operational from `Ke` state onward (started at line 292).

### Recommendation

Add `self.state.try_as_active()?;` at the start of `encrypt_alert`.

---

## Finding 4: No Cryptographic Binding Between KE Server Key and Handshake Commitment

**Severity:** High
**File:** `crates/components/key-exchange/src/exchange.rs` (lines 215–226, 381–393) and `crates/tls/mpc/src/leader.rs` (lines 464–488, 592–637)

### Description

The server's ephemeral public key used in the ECDH computation is sent to the follower through the KE context channel (`ctx.io_mut().send(server_key)`), while the handshake commitment is constructed from separate `server_kx_details` data. There is no cryptographic mechanism ensuring these refer to the same key. A malicious leader implementation could supply different keys through the two channels.

### Affected Code

The server key enters the KE protocol:
```rust
// exchange.rs line 220-221 (set_server_key)
self.ctx.io_mut().send(server_key).await?;
self.server_key = Some(server_key);
```

The handshake commitment is built from separate state:
```rust
// leader.rs line 592-606 (prepare_encryption)
let handshake_data = HandshakeData::new(
    server_cert_details.clone(),  // contains certificate with server identity
    server_kx_details.clone(),    // contains server's ephemeral key + signature
    client_random,
    server_random,
);
let (_, handshake_commitment) = handshake_data.clone().hash_commit();
```

These two keys are set independently via `set_server_key_share` (line 464) and `set_server_kx_details` (line 504).

### Attack Chain

1. Malicious leader modifies their TLS backend to call `set_server_key_share` with their own key pair (Key_A, for which they know the private key).
2. Leader calls `set_server_kx_details` with legitimate server Key_B's exchange details (captured from a real connection or fabricated with a self-signed cert).
3. The ECDH computation uses Key_A. Since the leader knows Key_A's private key AND the follower's public key (received during KE setup at line 333), the leader can independently compute the full PMS: `PMS = x(Key_A * (leader_priv + follower_pub))`.
4. The handshake commitment binds to Key_B's data. Post-hoc verification checks Key_B's certificate.
5. With knowledge of the full PMS, the leader derives all session keys locally.
6. The leader fabricates arbitrary "server" responses, computes valid AEAD tags, and sends them to the follower via `CommitMessage`.
7. The follower accepts the fabricated session as authentic.

### Evidence

- `set_server_key_share` (leader.rs, line 464) and `set_server_kx_details` (leader.rs, line 504) are independent Backend calls with no cross-validation.
- The follower receives the server key in `compute_pms` (exchange.rs, line 387) via `ctx.io_mut().expect_next()` with no binding to the commitment.
- The follower stores the received key in `MpcTlsFollowerData.server_key` (follower.rs, line 296-299) and the commitment separately in `handshake_commitment`.
- No code verifies that these two values are consistent.

### Recommendation

The protocol should cryptographically bind the server key used in the KE computation to the handshake commitment. Options include:
1. Include the raw server key bytes in the commitment and verify on the follower side before proceeding with ECDH.
2. Have the follower independently hash the received server key and compare with a value derived from the commitment.

---

## Finding 5: Multiplexer Connection Errors Silently Swallowed

**Severity:** Medium
**File:** `crates/common/src/mux.rs`
**Lines:** 32–48

### Description

`MuxFuture::poll_with` catches muxer errors and only logs them at `error!` level, then continues polling the user-supplied future. This means transport-layer failures (connection resets, protocol violations) are silently ignored. The MPC protocol continues operating on a broken connection, which can cause:
- Indefinite hangs when the MPC protocol tries to send/receive on closed channels
- Partial protocol execution where some messages succeed and others fail silently
- Potential state desynchronization between leader and follower

### Affected Code

```rust
// mux.rs line 32-48
pub async fn poll_with<F, R>(&mut self, fut: F) -> R
where
    F: Future<Output = R>,
{
    let mut fut = Box::pin(fut.fuse());
    loop {
        futures::select! {
            res = fut => return res,
            res = &mut self.0 => if let Err(e) = res {
                error!("mux error: {:?}", e);
                // Error is logged and execution continues
            },
        }
    }
}
```

### Attack Chain

1. An attacker performs a network-level attack (TCP reset, man-in-the-middle connection drop).
2. The yamux connection error is caught by `poll_with`.
3. The error is logged but the MPC protocol future continues.
4. Subsequent MPC operations may hang or produce inconsistent results.
5. In a race condition, partial state may be committed before the error propagates through the MPC channel.

### Evidence

- Line 43: `if let Err(e) = res { error!("mux error: {:?}", e); }` — error is logged but not propagated.
- No mechanism to abort the user future when the muxer fails.

### Recommendation

Propagate the muxer error to the caller, or cancel the user future when the muxer fails fatally.

---

## Finding 6: Follower Accepts Duplicate `Commit` Messages

**Severity:** Medium
**File:** `crates/tls/mpc/src/follower.rs`
**Lines:** 547–560

### Description

The follower's `commit()` method does not guard against being called multiple times. If a malicious leader sends the `Commit` message more than once, the follower will:
1. Set `self.committed = true` (idempotent, already true).
2. Check if the buffer is non-empty and, if so, call `self.decrypter.decode_key_blind()` again.

The second call to `decode_key_blind` attempts to re-decode the AEAD key in the underlying MPC protocol, which may cause a panic, protocol error, or undefined behavior depending on the MPC VM's handling of duplicate decode requests.

### Affected Code

```rust
// follower.rs line 547-560
async fn commit(&mut self) -> Result<(), MpcTlsError> {
    let Active { buffer, .. } = self.state.try_as_active()?;
    // No check: if self.committed { return Ok(()); }
    debug!("leader committed transcript");
    self.committed = true;
    if !buffer.is_empty() {
        self.decrypter.decode_key_blind().await?;
    }
    Ok(())
}
```

Compare with the leader's `commit()` (leader.rs, line 334-336) which correctly guards:
```rust
if self.committed {
    return Ok(());
}
```

### Attack Chain

1. Leader sends `CommitMessage` to queue a ciphertext in the follower's buffer.
2. Leader sends `Commit` → follower calls `decode_key_blind`, revealing the key.
3. Leader sends `Commit` again → follower calls `decode_key_blind` a second time.
4. The duplicate decode operation causes an error or panic in the MPC VM, crashing the follower.

### Evidence

- Leader's `commit()` (leader.rs, line 335): `if self.committed { return Ok(()); }` — guarded.
- Follower's `commit()` (follower.rs, line 547): no such guard — unguarded.

### Recommendation

Add an early return guard at the start of the follower's `commit()`:
```rust
if self.committed {
    return Ok(());
}
```

---

## Finding 7: GHASH Data Construction Can Overflow on Large Inputs

**Severity:** Low
**File:** `crates/components/aead/src/aes_gcm/tag.rs`
**Lines:** 159, 165, 169

### Description

The `build_ghash_data` function computes `(aad.len() as u64) * 8` for the bit-length encoding and `(aad.len() / 16) + (aad.len() % 16 != 0) as usize` for padding block count. On platforms where `usize` is 64-bit, the multiplication `aad.len() as u64 * 8` overflows if `aad.len() > 2^61`. More practically, `aad_padded_block_count * 16` can overflow on 32-bit platforms when `aad.len() > (usize::MAX / 16)`, producing a smaller-than-expected resize and corrupting the GHASH computation.

### Affected Code

```rust
// tag.rs line 158-178
fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;  // overflow if len > 2^61
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
    aad.resize(aad_padded_block_count * 16, 0);  // overflow on 32-bit if large

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);  // overflow on 32-bit
    ...
}
```

### Attack Chain

On a 32-bit platform:
1. Attacker provides AAD or ciphertext larger than ~256 MB.
2. `aad_padded_block_count * 16` wraps, producing a small value.
3. `aad.resize(small_value, 0)` truncates the AAD.
4. The GHASH is computed over truncated data, producing an incorrect tag.
5. The incorrect tag may match a forged message's tag by coincidence or selective construction.

While TLS AAD is fixed at 13 bytes (making this impractical in normal usage), the function interface accepts arbitrary-length inputs and lacks bounds checking.

### Recommendation

Add `assert!(aad.len() <= (1 << 36))` and `assert!(ciphertext.len() <= (1 << 36))` consistent with the GCM specification's maximum input sizes.
