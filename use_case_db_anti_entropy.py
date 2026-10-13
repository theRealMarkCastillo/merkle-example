"""
Use Case 2: Distributed Database Anti-Entropy / Synchronization (DynamoDB / Cassandra Pattern)

THE PROBLEM:
In distributed, masterless databases (like Apache Cassandra, Amazon Dynamo, or Riak),
multiple replicas store millions of key-value rows.
- Network glitches or node restarts occasionally cause replicas to drift (diverge).
- Naive Anti-Entropy: Send all 1,000,000 keys over the network between replicas to find differences.
  Cost: Gigabytes of network bandwidth and high disk I/O on every periodic health sync.

THE MERKLE SOLUTION:
- Every replica puts each key into one of a FIXED number of buckets
  (bucket = SHA-256(key) mod NUM_BUCKETS), similar to Cassandra's token ranges.
- Each bucket's contents are hashed into one leaf, and a Merkle tree is built over
  the buckets. A key's bucket never changes, so inserting, updating or deleting a key
  changes exactly ONE leaf, and every replica's tree has the same shape.
  (Building leaves from a sorted list of keys instead would break this: one insert
  shifts every later key into a different leaf, so the whole tail looks "different".)
- The two replicas compare only their Merkle Roots:
  - If roots match: The replicas are identical! Total bandwidth used: 32 bytes.
  - If roots differ: Replicas compare child hashes, drilling down ONLY into the
    divergent branches, then exchange the rows of just the mismatched buckets.
- Complexity: O(K * log B) hashes plus the contents of K buckets, rather than all N rows.

Simplification: repair uses Last-Write-Wins on a version number. Real systems also
use tombstones so that deletes propagate instead of being "repaired" back.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from merkle_tree import MerkleTree

# Fixed and agreed by all replicas, so their trees always have identical shape.
NUM_BUCKETS = 64

Row = Tuple[str, int]  # (value, version)


def bucket_of(key: str) -> int:
    """Stable bucket assignment: depends only on the key, never on other keys."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % NUM_BUCKETS


class DatabaseReplica:
    """
    Represents a distributed database storage node maintaining a key-value store.
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.storage: Dict[str, Row] = {}  # key -> (value, version)
        self.merkle_tree: Optional[MerkleTree] = None

    def put(self, key: str, value: str, version: int) -> None:
        """Writes or updates a key-value pair."""
        self.storage[key] = (value, version)

    def bucket_rows(self, bucket: int) -> Dict[str, Row]:
        """All rows stored in one bucket (what gets streamed during repair)."""
        return {k: row for k, row in self.storage.items() if bucket_of(k) == bucket}

    def rebuild_merkle_tree(self) -> None:
        """
        Builds a Merkle tree with one leaf per bucket. Rows inside a bucket are
        sorted and JSON-encoded so both replicas serialize them identically.
        """
        buckets: List[List[str]] = [[] for _ in range(NUM_BUCKETS)]
        for key, (val, ver) in sorted(self.storage.items()):
            buckets[bucket_of(key)].append(json.dumps([key, val, ver]))
        self.merkle_tree = MerkleTree(["\n".join(rows) for rows in buckets])

    def get_tree(self) -> MerkleTree:
        if self.merkle_tree is None:
            self.rebuild_merkle_tree()
        assert self.merkle_tree is not None
        return self.merkle_tree

    def get_merkle_root(self) -> str:
        return self.get_tree().root


@dataclass
class SyncReport:
    divergent_keys: List[str] = field(default_factory=list)
    divergent_buckets: List[int] = field(default_factory=list)
    hashes_exchanged: int = 0
    rows_exchanged: int = 0


def find_divergent_buckets(tree_a: MerkleTree, tree_b: MerkleTree) -> Tuple[List[int], int]:
    """
    Walks both trees from the root down, descending only into subtrees whose
    hashes differ. Returns (divergent_bucket_indices, hashes_exchanged).
    """
    if tree_a.size != tree_b.size:
        raise ValueError("Replicas must use the same number of buckets")

    hashes_exchanged = 2  # Root of A and Root of B
    if tree_a.root == tree_b.root:
        return [], hashes_exchanged

    mismatched: Set[int] = {0}
    # Traverse from top (root) down to bottom (leaves at level 0)
    for depth in range(len(tree_a.levels) - 1, 0, -1):
        child_level_a = tree_a.levels[depth - 1]
        child_level_b = tree_b.levels[depth - 1]

        next_mismatched: Set[int] = set()
        for idx in mismatched:
            for child in (idx * 2, idx * 2 + 1):
                if child < len(child_level_a):
                    hashes_exchanged += 2
                    if child_level_a[child] != child_level_b[child]:
                        next_mismatched.add(child)
        mismatched = next_mismatched

    return sorted(mismatched), hashes_exchanged


def compare_merkle_nodes(rep_a: DatabaseReplica, rep_b: DatabaseReplica) -> SyncReport:
    """
    Simulates anti-entropy Merkle tree comparison between two replicas:
    find mismatched buckets via the trees, then diff only those buckets' rows.
    """
    buckets, hashes = find_divergent_buckets(rep_a.get_tree(), rep_b.get_tree())
    report = SyncReport(divergent_buckets=buckets, hashes_exchanged=hashes)

    for bucket in buckets:
        rows_a = rep_a.bucket_rows(bucket)
        rows_b = rep_b.bucket_rows(bucket)
        report.rows_exchanged += len(rows_a) + len(rows_b)
        for key in sorted(rows_a.keys() | rows_b.keys()):
            if rows_a.get(key) != rows_b.get(key):
                report.divergent_keys.append(key)

    report.divergent_keys.sort()
    return report


def repair_replicas(
    rep_a: DatabaseReplica,
    rep_b: DatabaseReplica,
    divergent_keys: List[str],
) -> None:
    """
    Repairs divergent keys using Last-Write-Wins (highest version, ties broken by
    value so both replicas pick the same winner). Missing rows count as oldest.
    """
    for key in divergent_keys:
        row_a = rep_a.storage.get(key)
        row_b = rep_b.storage.get(key)
        candidates = [row for row in (row_a, row_b) if row is not None]
        winner = max(candidates, key=lambda row: (row[1], row[0]))

        if row_a != winner:
            rep_a.put(key, *winner)
            print(f"  Synced '{key}' -> Replica A updated to version {winner[1]}")
        if row_b != winner:
            rep_b.put(key, *winner)
            print(f"  Synced '{key}' -> Replica B updated to version {winner[1]}")

    rep_a.rebuild_merkle_tree()
    rep_b.rebuild_merkle_tree()


def run_db_anti_entropy_use_case():
    print("=" * 72)
    print(" USE CASE 2: Distributed Database Anti-Entropy (Cassandra/DynamoDB)")
    print("=" * 72)

    total_records = 512
    print(f"\n1. Initializing two database replicas with {total_records} identical records")
    print(f"   (hashed into {NUM_BUCKETS} fixed buckets = {NUM_BUCKETS} Merkle leaves)...")
    node_a = DatabaseReplica("Node-East-1")
    node_b = DatabaseReplica("Node-West-1")

    for i in range(total_records):
        key = f"user_{i:04d}"
        val = f"account_state_{i}"
        node_a.put(key, val, version=1)
        node_b.put(key, val, version=1)

    node_a.rebuild_merkle_tree()
    node_b.rebuild_merkle_tree()

    print(f"  Node A Merkle Root: {node_a.get_merkle_root()[:24]}...")
    print(f"  Node B Merkle Root: {node_b.get_merkle_root()[:24]}...")

    # Routine sync check when replicas are identical
    print("\n2. Routine Health Check (Replicas are in sync):")
    report = compare_merkle_nodes(node_a, node_b)
    print(f"  Divergent keys found: {len(report.divergent_keys)}")
    print(f"  Network traffic: Only {report.hashes_exchanged} root hashes (64 bytes) exchanged!")
    print(f"  Full table transfer avoided: {total_records} records skipped!")

    # 3. Simulate drift, including an INSERT (which shifts nothing with fixed buckets)
    print("\n3. Network partition occurred! Drift on 4 of 513 keys:")
    node_a.put("user_0042", "updated_balance_999", version=2)
    node_a.put("user_0256", "email_verified_true", version=2)
    node_b.put("user_0499", "new_shipping_address", version=2)
    node_b.put("user_0100a", "brand_new_signup", version=1)
    print("  - user_0042 updated on Node A (v2)")
    print("  - user_0256 updated on Node A (v2)")
    print("  - user_0499 updated on Node B (v2)")
    print("  - user_0100a INSERTED on Node B only")

    node_a.rebuild_merkle_tree()
    node_b.rebuild_merkle_tree()
    print(f"\n  Node A Root (diverged): {node_a.get_merkle_root()[:24]}...")
    print(f"  Node B Root (diverged): {node_b.get_merkle_root()[:24]}...")

    # 4. Anti-entropy repair using Merkle tree comparison
    print("\n4. Running Merkle Tree Anti-Entropy sync:")
    report = compare_merkle_nodes(node_a, node_b)
    print(f"  Mismatched buckets: {report.divergent_buckets} (of {NUM_BUCKETS})")
    print(f"  Hashes exchanged to locate them: {report.hashes_exchanged} (~{report.hashes_exchanged * 32} bytes)")
    print(f"  Rows exchanged from those buckets: {report.rows_exchanged} (vs. {2 * total_records + 1} for a full comparison)")
    print(f"  Divergent keys pinpointed: {report.divergent_keys}")

    # 5. Repair only the divergent records
    print("\n5. Applying repairs for divergent keys:")
    repair_replicas(node_a, node_b, report.divergent_keys)

    print("\n6. Post-Repair Verification:")
    print(f"  Node A Root: {node_a.get_merkle_root()[:24]}...")
    print(f"  Node B Root: {node_b.get_merkle_root()[:24]}...")
    in_sync = node_a.get_merkle_root() == node_b.get_merkle_root()
    print(f"  Roots match: {in_sync} {'✓ Replicas in sync!' if in_sync else '✗ STILL DIVERGED'}")


if __name__ == "__main__":
    run_db_anti_entropy_use_case()
