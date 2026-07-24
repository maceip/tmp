# TLSNotary Security Audit Report

**Date:** 2026-07-24
**Scope:** WASM bindings, formats/selective disclosure, data parsing, Merkle tree, transcript handling, substring proofs, serde patterns
**Exclusions:** Findings already documented (WASM bincode size limits, selective disclosure control character injection, offline HandshakeSummary::verify() missing, SessionHeader sent_len/recv_len not verified)

---

## Finding 1: MerkleProof.verify() Uses `assert!` Instead of Returning Errors — Panic-Based DoS

**Severity:** High
**File:** `crates/core/src/merkle.rs`, lines 72–81
**Category:** Denial of Service via panic in verification path

### Description

`MerkleProof::verify()` uses `assert_eq!` and `assert!` to validate preconditions (matching lengths of `leaf_indices`/`leaf_hashes`, and checking for duplicate indices). These will **panic** and abort the process/WASM instance instead of returning a `Result::Err`.

```rust
pub fn verify(
    &self,
    root: &MerkleRoot,
    leaf_indices: &[usize],
    leaf_hashes: &[Hash],
) -> Result<(), MerkleError> {
    assert_eq!(
        leaf_indices.len(),
        leaf_hashes.len(),
        "leaf indices length must match leaf hashes length"
    );
    assert!(
        !leaf_indices.iter().contains_dups(),
        "duplicate indices provided {:?}",
        leaf_indices
    );
    // ...
}
```

### Attack Chain

1. An attacker crafts a malicious `SubstringsProof` (via deserialized bytes) where the commitment openings produce duplicate `CommitmentId` indices when collected in `SubstringsProof::verify()` (line 279 of `substrings.rs`: `indices.push(id.to_inner() as usize)`).
2. During `SubstringsProof::verify()`, when `inclusion_proof.verify()` is called at line 307, the duplicate indices trigger `assert!(!leaf_indices.iter().contains_dups(), ...)`.
3. This panics the entire WASM instance or Rust process, causing a denial of service.

Note: `SubstringsProof::verify()` iterates over a `HashMap<CommitmentId, ...>`, which should produce unique keys. However, the `CommitmentId` is a `u32` wrapper, and the duplicate check exists as a defense-in-depth mechanism that **should** use `Result::Err` rather than `assert!` to avoid giving an attacker a guaranteed crash path if any upstream invariant is violated.

The `MerkleTree::proof()` method at line 162 also uses `assert!` for sorted indices, which is similarly problematic if that function is reachable with untrusted input.

### Evidence

- `crates/core/src/merkle.rs:72-81` — assert macros in `verify()`
- `crates/core/src/merkle.rs:162-164` — assert in `proof()`
- `crates/core/src/proof/substrings.rs:306-308` — caller site

### Recommendation

Replace `assert!` / `assert_eq!` with proper error returns:

```rust
if leaf_indices.len() != leaf_hashes.len() {
    return Err(MerkleError::LengthMismatch);
}
if leaf_indices.iter().contains_dups() {
    return Err(MerkleError::DuplicateIndices);
}
```

---

## Finding 2: Attacker-Controlled `MerkleProof.total_leaves` Field After Deserialization

**Severity:** High
**File:** `crates/core/src/merkle.rs`, lines 49–57, 96
**Category:** Proof forgery / verification bypass via deserialized field manipulation

### Description

The `MerkleProof` struct contains a `total_leaves: usize` field that is serialized and deserialized alongside the proof. During verification (line 96), this attacker-controlled value is passed directly to the underlying `rs_merkle` verification:

```rust
if !self
    .proof
    .verify(root.to_inner(), &indices, &hashes, self.total_leaves)
{
    return Err(MerkleError::MerkleProofVerificationFailed);
}
```

When the `MerkleProof` is deserialized from an attacker-provided `SubstringsProof` (via `TlsProof::deserialize()` in WASM), the `total_leaves` value is fully attacker-controlled.

### Attack Chain

1. Attacker creates a legitimate proof, then modifies the serialized `total_leaves` value.
2. The `rs_merkle` library's `MerkleProof::verify()` uses `total_leaves` to reconstruct the expected tree shape. By manipulating this value, the attacker may cause verification to pass with an incomplete or malformed proof for a different tree topology.
3. While `rs_merkle` 1.4 does validate tree structure, the trust boundary is incorrectly drawn: `total_leaves` should be derived from the signed `SessionHeader`, not from the proof itself. The Notary signs the Merkle root but not the leaf count, so a prover who wants to present a subset of commitments as if they were the complete set could manipulate `total_leaves`.

### Evidence

- `crates/core/src/merkle.rs:49-57` — `MerkleProof` struct with `total_leaves` as serialized field
- `crates/core/src/merkle.rs:94-98` — `self.total_leaves` used directly in verification
- `crates/core/src/proof/substrings.rs:306-308` — verification call site
- `crates/core/src/merkle.rs:322` — test explicitly modifies `total_leaves` and expects failure, but the trust model issue remains

### Recommendation

The `total_leaves` count should be stored in or derived from the `SessionHeader` (which is signed by the Notary), rather than being stored in the `MerkleProof` itself. Alternatively, the verification flow should cross-check `total_leaves` against a trusted source.

---

## Finding 3: WASM `HttpRequest` Header Name/Value Injection — No Validation at JS/Rust Boundary

**Severity:** Medium
**File:** `crates/wasm/src/types.rs`, lines 42–67
**Category:** HTTP Header Injection

### Description

The `HttpRequest` struct accepts a `HashMap<String, Vec<u8>>` for headers from JavaScript. The `TryFrom<HttpRequest>` implementation passes header names and values directly to `hyper::Request::builder().header(name, value)` without any validation:

```rust
for (name, value) in value.headers {
    builder = builder.header(name, value);
}
```

The header values are `Vec<u8>`, allowing raw bytes. While hyper does perform some validation, accepting raw bytes from JavaScript at the WASM boundary means an attacker controlling the JS side can attempt to inject:
- Header names containing `:`, spaces, or other invalid characters
- Header values containing `\r\n` sequences for response splitting (though hyper blocks this)

The `uri` field is also passed unchecked and could contain encoded path traversal sequences or CRLF injection attempts targeting the HTTP/1.1 request line.

### Attack Chain

1. Malicious JavaScript code constructs an `HttpRequest` with crafted header names/values (e.g., `"Host\r\nInjected-Header"` as a key).
2. The WASM binding directly forwards these to hyper's request builder.
3. While hyper's `HeaderName` and `HeaderValue` parsing provides some safety, the lack of validation at the trust boundary means the defense depends entirely on hyper's implementation details, and the error messages may leak internal state.

### Evidence

- `crates/wasm/src/types.rs:42-47` — `HttpRequest` struct with raw `HashMap<String, Vec<u8>>` headers
- `crates/wasm/src/types.rs:54-56` — direct forwarding to hyper builder

### Recommendation

Validate header names and values at the WASM boundary before passing to hyper. Reject header names containing non-token characters and values containing `\r` or `\n`.

---

## Finding 4: `FuturesIo::poll_read` — Uninitialized Memory Exposure to AsyncRead Implementation

**Severity:** Medium
**File:** `crates/wasm/src/io.rs`, lines 66–86
**Category:** Memory Safety — Uninitialized Memory Read

### Description

The `FuturesIo` adapter converts between `hyper::rt::Read` and `futures::AsyncRead`. In `poll_read`, it creates a mutable byte slice from `MaybeUninit<u8>` memory:

```rust
let buf_slice = unsafe {
    slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
};

let n = match futures::AsyncRead::poll_read(self.project().inner, cx, buf_slice) {
    Poll::Ready(Ok(n)) => n,
    other => return other.map_ok(|_| ()),
};
```

The safety comment says "buf_slice should only be written to," but the `futures::AsyncRead::poll_read` contract does not guarantee this. If the underlying `AsyncRead` implementation (the WebSocket stream `WsStream` in this case) reads from the buffer before writing to it, it would observe uninitialized memory. The struct's `new()` method documents this as an invariant but cannot enforce it at the type level.

### Attack Chain

1. If the `WsStream` or any future wrapper reads from `buf_slice` before writing, it would access uninitialized memory.
2. In practice, `WsStream` from `ws_stream_wasm` writes into the buffer without reading, so this is currently safe. However, the unsound abstraction means any change to the underlying transport could silently introduce undefined behavior.
3. In debug builds or with certain allocators, the uninitialized bytes could contain sensitive data from previous allocations.

### Evidence

- `crates/wasm/src/io.rs:72-74` — unsafe cast from `MaybeUninit<u8>` to `u8`
- `crates/wasm/src/io.rs:24-26` — safety requirement documented but not enforced

### Recommendation

Use `ReadBuf` or `BorrowedBuf` approaches that zero-initialize the buffer, or use a wrapper that guarantees the inner reader never reads from the uninitialized portion. At minimum, zero the buffer before passing it.

---

## Finding 5: `SubstringsProof::verify()` — `opening.recover()` Panics on Length Mismatch Instead of Returning Error

**Severity:** Medium
**File:** `crates/core/src/commitment/blake3.rs`, lines 69–74; `crates/core/src/proof/substrings.rs`, line 280
**Category:** Denial of Service via panic in verification path

### Description

During `SubstringsProof::verify()`, for each opening, `opening.recover(&encodings)` is called (line 280). Inside `Blake3Opening::recover()`, there is an assertion:

```rust
pub fn recover(&self, encodings: &[EncodedValue<Full>]) -> Blake3Commitment {
    assert_eq!(
        encodings.len(),
        self.data.len(),
        "encodings and data must have the same length"
    );
```

The number of encodings is derived from the `CommitmentInfo.ranges` field (which comes from the deserialized proof), while `self.data.len()` comes from the `Blake3Opening.data` field (also from the deserialized proof). A crafted proof where `ranges` and `data` have inconsistent lengths will trigger this `assert_eq!` and panic.

Although `SubstringsProof::verify()` does check `opening.data().len() != opened_len` at line 235, this check uses `opening.data()` (length of the opening data) against `ranges.len()` (sum of range lengths). The `recover()` call at line 280 checks `encodings.len()` (number of individual byte indices from range iteration) against `self.data.len()`. These are the same comparison **only if** `get_value_ids` produces one ID per byte in the ranges, which it does. So under normal operation this is redundant, but the panic path remains dangerous if any code path changes.

### Attack Chain

1. Attacker crafts a `SubstringsProof` where `CommitmentInfo.ranges` and `Blake3Opening.data` have subtly inconsistent lengths that bypass the check at line 235 (e.g., through edge cases in `RangeSet::len()` behavior).
2. `Blake3Opening::recover()` panics, crashing the verifier process or WASM instance.

### Evidence

- `crates/core/src/commitment/blake3.rs:70-74` — assert_eq! in recover()
- `crates/core/src/proof/substrings.rs:280` — caller site
- `crates/core/src/proof/substrings.rs:234-236` — existing (potentially bypassable) check

### Recommendation

Replace `assert_eq!` in `recover()` with a `Result::Err` return. Never use panicking assertions in verification paths that process attacker-controlled input.

---

## Finding 6: `TranscriptSlice` Range/Data Length Mismatch Not Validated in `RedactedTranscript::new()`

**Severity:** Medium
**File:** `crates/core/src/transcript.rs`, lines 65–79
**Category:** Logic bug — silent data corruption

### Description

`RedactedTranscript::new()` accepts `TranscriptSlice` values and copies their data into a buffer using:

```rust
pub fn new(len: usize, slices: Vec<TranscriptSlice>) -> Self {
    let mut data = vec![0u8; len];
    let mut auth = RangeSet::default();
    for slice in slices {
        data[slice.range()].copy_from_slice(slice.data());
        auth = auth.union(&slice.range());
    }
```

There is **no validation** that `slice.range().len() == slice.data().len()`. If these differ, `copy_from_slice` will panic at runtime. The `TranscriptSlice::new()` constructor also performs no validation:

```rust
pub fn new(range: Range<usize>, data: Vec<u8>) -> Self {
    Self { range, data }
}
```

This is called from `SubstringsProof::verify()` (lines 312-319) where the slices are constructed from the verified data. While the current caller constructs consistent slices, the public API of `TranscriptSlice` allows inconsistent construction.

### Attack Chain

1. If any code path constructs a `TranscriptSlice` where `range.len() != data.len()`, the `copy_from_slice` in `RedactedTranscript::new()` will panic.
2. This is currently mitigated by the fact that `SubstringsProof::verify()` constructs slices from already-validated data. However, `TranscriptSlice::new()` is a public constructor that does not enforce this invariant.

### Evidence

- `crates/core/src/transcript.rs:65-71` — no length validation
- `crates/core/src/transcript.rs:140-141` — public constructor without validation
- `crates/core/src/proof/substrings.rs:312-319` — current (correct) usage

### Recommendation

Add a validation check in `TranscriptSlice::new()`:

```rust
pub fn new(range: Range<usize>, data: Vec<u8>) -> Self {
    assert_eq!(range.len(), data.len(), "range and data length mismatch");
    Self { range, data }
}
```

Or better, return a `Result`.

---

## Finding 7: Merkle Tree Deserialization Accepts Arbitrary Leaf Count With No Upper Bound

**Severity:** Medium
**File:** `crates/core/src/merkle.rs`, lines 203–218
**Category:** Denial of Service via resource exhaustion during deserialization

### Description

The `merkle_tree_deserialize` function deserializes a `Vec<u8>` of leaf hashes and constructs a full Merkle tree:

```rust
fn merkle_tree_deserialize<'de, D>(
    deserializer: D,
) -> Result<MerkleTree_rs_merkle<Sha256>, D::Error> {
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    if bytes.len() % 32 != 0 {
        return Err(serde::de::Error::custom("leaves must be 32 bytes"));
    }
    let leaves: Vec<[u8; 32]> = bytes.chunks(32).map(|c| c.try_into().unwrap()).collect();
    Ok(MerkleTree_rs_merkle::<Sha256>::from_leaves(leaves.as_slice()))
}
```

There is no upper bound on the number of leaves. A malicious payload with millions of 32-byte leaves will cause `MerkleTree::from_leaves()` to build a full in-memory tree, consuming O(n) memory and O(n log n) CPU time. This is separate from the known bincode size limit issue — this is about the semantic layer not imposing its own limit.

Note: `MerkleProof` deserialization similarly has no bound on proof size.

### Attack Chain

1. Attacker sends a serialized `NotarizedSession` or `TlsProof` containing a `MerkleTree` or `TranscriptCommitments` with an extremely large number of leaves.
2. Deserialization allocates unbounded memory to build the Merkle tree.
3. The WASM instance or verifier process runs out of memory and crashes.

### Evidence

- `crates/core/src/merkle.rs:203-218` — no size limit check
- `crates/core/src/merkle.rs:125-133` — `merkle_proof_deserialize` similarly unbounded
- `crates/wasm/src/types.rs:152-154` — WASM deserialize entry point

### Recommendation

Add a maximum leaf count check before constructing the tree:

```rust
const MAX_MERKLE_LEAVES: usize = 10_000;
if leaves.len() > MAX_MERKLE_LEAVES {
    return Err(serde::de::Error::custom("too many leaves"));
}
```

---

## Finding 8: `SubstringsProof::verify()` — `CommitmentInfo` Direction and Ranges Trusted From Deserialized Proof

**Severity:** High
**File:** `crates/core/src/proof/substrings.rs`, lines 221–300
**Category:** Proof forgery — attacker controls commitment metadata

### Description

In `SubstringsProof::verify()`, the `CommitmentInfo` (containing `ranges` and `direction`) is deserialized alongside each opening in the `openings` HashMap. This metadata is trusted for:

1. Determining the transcript direction (sent vs received) — line 241/248
2. Computing range bounds checks — line 256–265
3. Generating encoding IDs — line 269–275
4. Placing data into the output buffer — line 288–299

The verification flow recovers the expected commitment hash using `opening.recover(&encodings)` (line 280), then verifies that hash is in the Merkle tree (line 306-308). However, the **encodings** are computed from the deserialized `CommitmentInfo.ranges` and `CommitmentInfo.direction` fields using `get_value_ids(&ranges, direction)` — these are used to derive the encoder output.

If an attacker can craft a `CommitmentInfo` with different ranges/direction than what was originally committed, the recovered hash would differ from the Merkle tree leaf, and verification would fail. This means the Merkle inclusion proof acts as a binding mechanism for the commitment metadata.

However, the `CommitmentInfo` is not directly hashed into the commitment — only the *encoding values* derived from it are. The security relies on the fact that different `(ranges, direction)` tuples produce different encoding IDs, which produce different encodings, which produce different hashes. If an encoding collision could be found (two different `(ranges, direction)` pairs producing identical encoding sequences), the commitment metadata could be swapped.

### Attack Chain

1. Attacker finds two different `(ranges, direction)` tuples that, when processed through `get_value_ids()` → `EncodingId::new()` → `encoder.encode_by_type()`, produce identical encoding sequences.
2. `EncodingId::new()` uses a 64-bit Blake3 hash (`u64::from_be_bytes(hash[..8])`), meaning collision resistance is only ~2^32 (birthday bound).
3. With 2^32 trial IDs, the attacker can find a collision and swap `CommitmentInfo` to re-attribute data to a different direction or range.

### Evidence

- `crates/core/src/lib.rs:41-48` — `EncodingId` uses only 64 bits of Blake3 (truncated)
- `crates/core/src/proof/substrings.rs:269-275` — encoding generation from `CommitmentInfo`
- `crates/core/src/transcript.rs:176-183` — `get_value_ids()` generates string IDs like `"tx/0"`, `"rx/0"`

### Recommendation

Use the full 256-bit Blake3 hash for encoding IDs instead of truncating to 64 bits. Alternatively, include the `CommitmentInfo` (ranges + direction) directly in the commitment hash computation so it is bound to the Merkle leaf.

---

## Finding 9: WASM `ProverConfig` — `.unwrap()` on Builder Calls Can Panic on Malformed JS Input

**Severity:** Medium
**File:** `crates/wasm/src/prover/config.rs`, lines 26, 33; `crates/wasm/src/verifier/config.rs`, lines 25, 30
**Category:** Denial of Service via panic on invalid configuration

### Description

Both `ProverConfig` and `VerifierConfig` conversion implementations use `.unwrap()` on builder results:

```rust
// prover/config.rs
let protocol_config = builder.build().unwrap();
tlsn_prover::tls::ProverConfig::builder()
    .id(value.id)
    .server_dns(value.server_dns)
    .protocol_config(protocol_config)
    .build()
    .unwrap()
```

```rust
// verifier/config.rs
let config_validator = builder.build().unwrap();
tlsn_verifier::tls::VerifierConfig::builder()
    .id(value.id)
    .protocol_config_validator(config_validator)
    .build()
    .unwrap()
```

These are called from `#[wasm_bindgen(constructor)]` methods, meaning they are directly invoked from JavaScript. If the builder fails (e.g., due to missing required fields, invalid `server_dns`, or conflicting configuration), the `.unwrap()` will panic and crash the WASM instance.

### Attack Chain

1. JavaScript code (potentially malicious or buggy) calls `new Prover({id: "", server_dns: "", max_sent_data: 0})`.
2. The builder may reject this configuration (empty server DNS, zero-size data limits).
3. `.unwrap()` panics, crashing the WASM runtime.

### Evidence

- `crates/wasm/src/prover/config.rs:26,33` — unwrap on builder results
- `crates/wasm/src/verifier/config.rs:25,30` — unwrap on builder results

### Recommendation

Return `Result<JsProver, JsError>` from the constructor and propagate builder errors using `?` or `.map_err()`.

---

## Summary Table

| # | Finding | Severity | File | Type |
|---|---------|----------|------|------|
| 1 | MerkleProof.verify() panics instead of returning errors | High | `merkle.rs:72-81` | DoS |
| 2 | Attacker-controlled `total_leaves` in deserialized MerkleProof | High | `merkle.rs:49-57,96` | Proof integrity |
| 3 | WASM HttpRequest header injection — no validation at JS/Rust boundary | Medium | `types.rs:42-67` | Injection |
| 4 | FuturesIo::poll_read exposes uninitialized memory | Medium | `io.rs:66-86` | Memory safety |
| 5 | Blake3Opening::recover() panics on length mismatch | Medium | `blake3.rs:69-74` | DoS |
| 6 | TranscriptSlice range/data length not validated | Medium | `transcript.rs:65-79` | Logic bug |
| 7 | Merkle tree deserialization accepts unbounded leaf count | Medium | `merkle.rs:203-218` | DoS |
| 8 | EncodingId uses truncated 64-bit hash — birthday-bound collision | High | `lib.rs:41-48` | Proof forgery |
| 9 | WASM config constructors panic on invalid input | Medium | `prover/config.rs`, `verifier/config.rs` | DoS |
