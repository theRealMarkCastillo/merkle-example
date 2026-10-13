# Merkle Hash Tree in Python

An educational, dependency-free implementation of a **Merkle Hash Tree** in Python, featuring tree construction, logarithmic audit proofs, tamper detection, an RFC 6962-compatible tree (verified against Certificate Transparency test vectors), three end-to-end use case simulations, and a comparison with competing data structures.

---

## What is a Merkle Tree?

A **Merkle Tree** (or Hash Tree) is a cryptographic binary tree where:
1. Every **leaf node** is a cryptographic hash of a data block (such as a transaction, file chunk, or database record).
2. Every **internal node** is the cryptographic hash of its child nodes' concatenated hashes.
3. The top node is the **Merkle Root**, which uniquely identifies and commits to the entire dataset.

```
                    [ Merkle Root ]
                        /     \
                       /       \
               [ Hash 0-1 ]   [ Hash 2-3 ]
                 /      \       /      \
            [ Hash 0 ] [ Hash 1 ] [ Hash 2 ] [ Hash 3 ]
                |          |          |          |
              Data 0     Data 1     Data 2     Data 3
```

---

## What Problems Do Merkle Trees Solve?

| Problem | Naive Solution | Merkle Tree Solution |
| :--- | :--- | :--- |
| **Verifying Membership** | Download and scan the entire dataset ($O(N)$ data). | Provide an audit path of $\lceil\log_2 N\rceil$ sibling hashes ($O(\log N)$ data). |
| **Blockchain / Smart Contract Storage** | Store 100k whitelist entries on-chain (~20,000 gas per new slot, ~2 billion gas total). | Store only **one 32-byte root** on-chain. |
| **Distributed DB Synchronization (Anti-Entropy)** | Transfer all database rows over the network to find differences. | Compare tree levels from root down; transfer **only** mismatched buckets. |
| **P2P File Downloads (BitTorrent/IPFS)** | Hash the whole file at the end, or ship one hash per piece in the metadata. | Verify each chunk immediately as it arrives; discard and ban bad peers instantly. |
| **Certificate Transparency (RFC 6962)** | Trusting centralized Certificate Authorities blindly. | Append-only public Merkle logs; browsers verify certificates with lightweight audit proofs. |

---

## End-to-End Use Cases (Runnable Examples)

### 1. Smart Contract Token Airdrop / Whitelist
- **File**: [`use_case_airdrop_whitelist.py`](use_case_airdrop_whitelist.py)
- **Problem**: Distributing tokens to thousands of users on a blockchain like Ethereum where storage is extremely expensive.
- **Solution**: The smart contract stores only the 32-byte Merkle root (plus the leaf count). An eligible user submits their leaf index, address, amount, and Merkle proof. The contract validates the proof in $O(\log N)$ operations, tracks claims by leaf index, and rejects double claims, tampered amounts, and proofs used at the wrong index.

### 2. Distributed Database Anti-Entropy Sync (Cassandra / DynamoDB)
- **File**: [`use_case_db_anti_entropy.py`](use_case_db_anti_entropy.py)
- **Problem**: Replicas in distributed databases (Cassandra, DynamoDB, Riak) drift due to network hiccups. Finding the few out-of-sync rows among millions of records without streaming the entire database across the network.
- **Solution**: Keys are hashed into a **fixed** number of buckets (like Cassandra's token ranges), with one Merkle leaf per bucket. A key never changes bucket, so an insert, update or delete changes exactly one leaf. Nodes compare roots (one round trip if in sync), then descend only into mismatched subtrees and exchange rows from just those buckets.

> [!NOTE]
> Building leaves from a sorted list of keys does **not** work: one insert shifts every later key into a different leaf, so the whole tail looks different. Fixed buckets avoid this.

### 3. P2P Chunk Integrity & Fast Bad-Peer Detection (BitTorrent / IPFS)
- **File**: [`use_case_p2p_chunk_verification.py`](use_case_p2p_chunk_verification.py)
- **Problem**: Downloading a large file from untrusted peers. Hashing the whole file at the end can't identify the bad peer; BitTorrent v1's one-hash-per-piece list grows with file size (BitTorrent v2, BEP 52, moved to Merkle trees).
- **Solution**: The metadata holds the Merkle root and chunk count. Each peer sends `(chunk_data, merkle_proof)`. The downloader verifies each chunk before writing it, rejecting corrupted chunks **and** genuine chunks sent under the wrong position, and bans the peer.

---

## How Audit Proofs (Merkle Paths) Work

To prove that **Data 1** is part of the tree with Root `R`:
1. The prover provides the original data `Data 1`, its index `1`, the tree size `4`, and the sibling hashes along the path to the root: `Hash 0`, then `Hash 2-3`.
2. The verifier works out from the index and tree size which side each sibling is on (`Hash 0` on the **left**, `Hash 2-3` on the **right**) and recomputes:
   $$\text{Hash 1} = \text{hash}(\text{Data 1})$$
   $$\text{Hash 0-1} = \text{hash}(\text{Hash 0} \parallel \text{Hash 1})$$
   $$\text{Recomputed Root} = \text{hash}(\text{Hash 0-1} \parallel \text{Hash 2-3})$$
3. If $\text{Recomputed Root} == \text{Expected Root}$, the proof is valid.

> [!IMPORTANT]
> The verifier derives the left/right sides itself rather than trusting directions sent by the prover. This binds the proof to one position: a genuine chunk or whitelist entry can't be passed off as a different index.

---

## Security Details (RFC 6962)

- **Domain separation**: leaves are hashed as `SHA256(0x00 || leaf_data)` and internal nodes as `SHA256(0x01 || left_hash || right_hash)`, so an internal node can't be passed off as a leaf (second-preimage attack).
- **Odd node counts**: when a level has an odd number of nodes, the last one is **promoted unchanged** to the next level. It is not duplicated: duplicating it (as Bitcoin does) makes `[A, B, C]` and `[A, B, C, C]` share a root, the flaw behind CVE-2012-2459.
- **Conformance**: roots are tested against an independent recursive RFC 6962 implementation and the Certificate Transparency known-answer vectors.

---

## Competing Data Structures

[`competing_methods_comparison.py`](competing_methods_comparison.py) implements and demonstrates:

| Structure | What it adds over a binary Merkle tree | Trade-off |
| :--- | :--- | :--- |
| **Sparse Merkle Tree** (256-bit key space) | Proofs of **non-membership**: a key's fixed slot is shown to be empty. Forged or replayed proofs are rejected. | Uncompressed proofs are 256 hashes (~8 KB); production SMTs compress them. |
| **Bloom Filter** | $O(1)$ membership checks in a few hundred bits. | Probabilistic (false positives) and no proof for a third party. |
| **MuHash** (3072-bit, as in Bitcoin Core) | Order-independent set fingerprint with $O(1)$ add/remove. | No membership proofs; needs a large modulus to be secure. |

---

## Files

| File | Contents |
| :--- | :--- |
| [`merkle_tree.py`](merkle_tree.py) | Core `MerkleTree` and `MerkleProof` classes, plus an interactive demo. |
| [`use_case_airdrop_whitelist.py`](use_case_airdrop_whitelist.py) | Use case 1: smart contract airdrop. |
| [`use_case_db_anti_entropy.py`](use_case_db_anti_entropy.py) | Use case 2: database replica sync. |
| [`use_case_p2p_chunk_verification.py`](use_case_p2p_chunk_verification.py) | Use case 3: P2P chunk verification. |
| [`competing_methods_comparison.py`](competing_methods_comparison.py) | Sparse Merkle tree, Bloom filter, MuHash. |
| [`test_merkle_tree.py`](test_merkle_tree.py) | 26 unit tests, including RFC 6962 vectors and regression tests for each bug found in review. |

---

## Running the Examples & Tests

```bash
# Run core Merkle Tree demo
python3 merkle_tree.py

# Run Use Case 1: Smart contract whitelist / airdrop
python3 use_case_airdrop_whitelist.py

# Run Use Case 2: Distributed database anti-entropy sync
python3 use_case_db_anti_entropy.py

# Run Use Case 3: P2P chunk verification & peer banning
python3 use_case_p2p_chunk_verification.py

# Run the competing data structures comparison
python3 competing_methods_comparison.py

# Run comprehensive test suite
python3 -m unittest test_merkle_tree.py
```
