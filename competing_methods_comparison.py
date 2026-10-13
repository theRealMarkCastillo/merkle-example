"""
Demonstration and Comparison of Merkle Trees vs. Competing Cryptographic Data Structures:

1. Binary Merkle Tree:
   - Proves membership in O(log2 N) size.
   - Fixed ordering; proving non-membership requires ordering or full scan.

2. Sparse Merkle Tree (SMT):
   - 256-bit key space (2^256 potential leaves), almost entirely empty.
   - Supports BOTH Membership proofs AND Non-Membership (non-inclusion) proofs in O(log N).

3. Bloom Filter:
   - Probabilistic set membership in O(1) space and time.
   - Extremely lightweight, but cannot provide cryptographic proofs and has false positives.

4. Homomorphic / Multiset Hash (MuHash):
   - Unordered set hashing where Hash(A + B) = Hash(A) * Hash(B) (mod P).
   - Order-independent: adding/removing items is an O(1) arithmetic operation.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from merkle_tree import hash_leaf, hash_children


# ==============================================================================
# 1. Sparse Merkle Tree (SMT) - Solves Proof of NON-Membership
# ==============================================================================

SMT_DEPTH = 256
SMT_EMPTY_LEAF = hashlib.sha256(b"\x00EMPTY").hexdigest()


def _default_hashes(depth: int) -> List[str]:
    """default[level] = hash of a completely empty subtree of that height."""
    hashes = [SMT_EMPTY_LEAF]
    for _ in range(depth):
        hashes.append(hash_children(hashes[-1], hashes[-1]))
    return hashes


SMT_DEFAULT_HASHES = _default_hashes(SMT_DEPTH)


@dataclass
class SMTProof:
    """
    A proof about one key in a Sparse Merkle Tree.

    Attributes:
        key: The key the proof is about.
        leaf_key / leaf_value: What is actually stored in that key's slot
                               (both None if the slot is empty).
        siblings: SMT_DEPTH sibling hashes, ordered from the leaf up to the root.
    """

    key: str
    leaf_key: Optional[str]
    leaf_value: Optional[str]
    siblings: List[str]


class SimpleSparseMerkleTree:
    """
    A Sparse Merkle Tree over a 256-bit key space: every possible key has a fixed
    leaf slot, slot = SHA-256(key). Almost all 2^256 slots are empty; empty subtrees
    use precomputed default hashes, so only paths to occupied slots are hashed.
    Key feature: Can prove that a key DOES NOT exist.

    Production SMTs (e.g. in Cosmos, Diem/Aptos) additionally compress the mostly-
    default siblings in proofs; this demo sends all 256 for clarity (~8 KB).
    """

    def __init__(self):
        # Sparse leaf storage: slot -> (key, value)
        self.leaves: Dict[int, Tuple[str, str]] = {}

    @staticmethod
    def slot_of(key: str) -> int:
        """Hashes a key to its 256-bit leaf slot."""
        return int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest(), "big")

    @staticmethod
    def leaf_hash(key: str, value: Optional[str]) -> str:
        # The stored key is part of the leaf, so a proof shows WHICH key occupies a slot.
        return hash_leaf(json.dumps([key, value]))

    def update(self, key: str, value: str) -> None:
        slot = self.slot_of(key)
        existing = self.leaves.get(slot)
        if existing is not None and existing[0] != key:
            raise ValueError(f"Slot collision between {existing[0]!r} and {key!r} (SHA-256 collision!)")
        self.leaves[slot] = (key, value)

    def _node_hash(self, level: int, index: int, slots: List[int]) -> str:
        """
        Hash of the subtree of height `level` at position `index`.
        `slots` lists the occupied leaf slots inside that subtree.
        """
        if not slots:
            return SMT_DEFAULT_HASHES[level]
        if level == 0:
            key, value = self.leaves[slots[0]]
            return self.leaf_hash(key, value)

        left_index = index * 2
        left_slots = [s for s in slots if (s >> (level - 1)) == left_index]
        right_slots = [s for s in slots if (s >> (level - 1)) != left_index]
        return hash_children(
            self._node_hash(level - 1, left_index, left_slots),
            self._node_hash(level - 1, left_index + 1, right_slots),
        )

    def get_root(self) -> str:
        return self._node_hash(SMT_DEPTH, 0, list(self.leaves))

    def get_proof(self, key: str) -> SMTProof:
        """Generates a proof for `key` that shows what its slot contains."""
        slot = self.slot_of(key)
        stored = self.leaves.get(slot)

        siblings: List[str] = []
        idx = slot
        for level in range(SMT_DEPTH):
            sibling_idx = idx ^ 1
            sibling_slots = [s for s in self.leaves if (s >> level) == sibling_idx]
            siblings.append(self._node_hash(level, sibling_idx, sibling_slots))
            idx >>= 1

        return SMTProof(
            key=key,
            leaf_key=stored[0] if stored else None,
            leaf_value=stored[1] if stored else None,
            siblings=siblings,
        )

    @classmethod
    def _recompute_root(cls, proof: SMTProof) -> Optional[str]:
        """
        Recomputes the root implied by a proof, or None if the proof is malformed.
        Sibling sides come from SHA-256(proof.key), never from the prover, so a
        proof for one key cannot be replayed for another.
        """
        if len(proof.siblings) != SMT_DEPTH:
            return None

        if proof.leaf_key is None:
            current = SMT_EMPTY_LEAF
        else:
            # A stored leaf can only sit in the queried key's slot if their slots match
            if cls.slot_of(proof.leaf_key) != cls.slot_of(proof.key):
                return None
            current = cls.leaf_hash(proof.leaf_key, proof.leaf_value)

        idx = cls.slot_of(proof.key)
        for sibling in proof.siblings:
            if idx & 1:
                current = hash_children(sibling, current)
            else:
                current = hash_children(current, sibling)
            idx >>= 1
        return current

    @classmethod
    def verify_membership(cls, proof: SMTProof, expected_root: str) -> bool:
        """True only if the key's slot holds this exact key (value = proof.leaf_value)."""
        return proof.leaf_key == proof.key and cls._recompute_root(proof) == expected_root

    @classmethod
    def verify_non_membership(cls, proof: SMTProof, expected_root: str) -> bool:
        """True only if the key's slot is empty (or held by a different key)."""
        return proof.leaf_key != proof.key and cls._recompute_root(proof) == expected_root


# ==============================================================================
# 2. Bloom Filter - Probabilistic, O(1) space, no cryptographic proof
# ==============================================================================

class SimpleBloomFilter:
    """
    Probabilistic set membership data structure.
    - True positive: Might be in set (with small false-positive probability).
    - False positive: Possible.
    - False negative: IMPOSSIBLE (if it says 'No', it's 100% not in set).
    - No cryptographic proof path.
    """

    def __init__(self, size_bits: int = 1024, num_hashes: int = 3):
        self.size = size_bits
        self.num_hashes = num_hashes
        self.bit_array = [0] * size_bits

    def _get_hashes(self, item: str) -> List[int]:
        hashes = []
        for seed in range(self.num_hashes):
            digest = hashlib.sha256(f"{seed}:{item}".encode()).digest()
            val = int.from_bytes(digest[:4], "big")
            hashes.append(val % self.size)
        return hashes

    def add(self, item: str) -> None:
        for idx in self._get_hashes(item):
            self.bit_array[idx] = 1

    def contains(self, item: str) -> bool:
        return all(self.bit_array[idx] == 1 for idx in self._get_hashes(item))


# ==============================================================================
# 3. Multiset Hash (MuHash) - Order Independent Set Hashing
# ==============================================================================

class SimpleMultisetHash:
    """
    Homomorphic / Multiset Hash using modular arithmetic.
    Hash(A U B) = (Hash(A) * Hash(B)) mod P.
    Properties:
    - Commutative: Hash({x, y}) == Hash({y, x}) (Order does NOT matter!).
    - O(1) Insertion & Deletion: Can remove an item by multiplying with modular inverse.
    - Great for tracking mempools or unordered database diffs.

    Security note: MuHash relies on discrete logarithms being hard in the
    multiplicative group mod P, so P must be about as large as a Diffie-Hellman
    modulus. A 256-bit prime would offer little security. This uses the same
    3072-bit prime as Bitcoin Core's MuHash3072: P = 2^3072 - 1103717.
    """

    PRIME = 2**3072 - 1103717
    ELEMENT_BYTES = 384  # 3072 bits

    def __init__(self):
        self.state: int = 1  # Multiplicative identity

    def _hash_to_int(self, item: str) -> int:
        # Expand each item to a full 3072-bit field element (Bitcoin uses ChaCha20
        # for this expansion; SHAKE-256 serves the same purpose here).
        expanded = hashlib.shake_256(item.encode("utf-8")).digest(self.ELEMENT_BYTES)
        val = int.from_bytes(expanded, "big")
        # Ensure non-zero element in field
        return (val % (self.PRIME - 1)) + 1

    def add(self, item: str) -> None:
        item_val = self._hash_to_int(item)
        self.state = (self.state * item_val) % self.PRIME

    def remove(self, item: str) -> None:
        item_val = self._hash_to_int(item)
        # Multiply by modular inverse to remove item
        inv = pow(item_val, -1, self.PRIME)
        self.state = (self.state * inv) % self.PRIME

    def digest(self) -> str:
        """Compresses the 3072-bit state to a 32-byte fingerprint."""
        return hashlib.sha256(self.state.to_bytes(self.ELEMENT_BYTES, "big")).hexdigest()


# ==============================================================================
# Comparison Runner
# ==============================================================================

def run_comparison_demo():
    print("=" * 76)
    print("       COMPARING MERKLE TREES WITH ALTERNATIVE DATA STRUCTURES      ")
    print("=" * 76)

    # --------------------------------------------------------------------------
    # Demo 1: Sparse Merkle Tree (Proof of Non-Membership)
    # --------------------------------------------------------------------------
    print("\n1. SPARSE MERKLE TREE (SMT): Proving NON-Membership")
    print("   Standard Merkle Trees prove membership. SMTs can also prove an item DOES NOT exist!")
    smt = SimpleSparseMerkleTree()
    smt.update("alice@example.com", "Active")
    smt.update("bob@example.com", "Active")
    smt_root = smt.get_root()
    print(f"   SMT Root: {smt_root[:24]}... (2^256 slots, 2 occupied)")

    # Prove membership for Alice
    alice_proof = smt.get_proof("alice@example.com")
    print(f"   [Membership Proof] alice@example.com = {alice_proof.leaf_value!r}: "
          f"{SimpleSparseMerkleTree.verify_membership(alice_proof, smt_root)} ✓")

    # Prove NON-membership for Mallory (Mallory does NOT exist in the tree)
    mallory_proof = smt.get_proof("mallory@example.com")
    print(f"   [Non-Membership Proof] mallory@example.com slot is empty: "
          f"{SimpleSparseMerkleTree.verify_non_membership(mallory_proof, smt_root)} ✓")
    print("   -> Cryptographically proves to a client that Mallory was never registered!")

    # Forgery attempts
    print("   Forgery attempts:")
    replayed = SMTProof("mallory@example.com", alice_proof.leaf_key, alice_proof.leaf_value, alice_proof.siblings)
    print(f"   - Replay Alice's proof as Mallory's membership:  "
          f"{'ACCEPTED ✗' if SimpleSparseMerkleTree.verify_membership(replayed, smt_root) else 'REJECTED ✓'}")
    hidden = SMTProof("alice@example.com", None, None, alice_proof.siblings)
    print(f"   - Claim Alice's slot is empty (hide her record):  "
          f"{'ACCEPTED ✗' if SimpleSparseMerkleTree.verify_non_membership(hidden, smt_root) else 'REJECTED ✓'}")

    # --------------------------------------------------------------------------
    # Demo 2: Bloom Filter
    # --------------------------------------------------------------------------
    print("\n2. BLOOM FILTER: Ultra-compact, O(1) membership, but NO cryptographic proof")
    bf = SimpleBloomFilter(size_bits=256, num_hashes=3)
    bf.add("user_100")
    bf.add("user_200")
    print(f"   Contains 'user_100': {bf.contains('user_100')} (True positive)")
    print(f"   Contains 'user_999': {bf.contains('user_999')} (True negative)")
    print("   Trade-off: Fast and tiny (256 bits), but cannot prove inclusion to an untrusted third party.")

    # --------------------------------------------------------------------------
    # Demo 3: Multiset / Homomorphic Hash (MuHash)
    # --------------------------------------------------------------------------
    print("\n3. MULTISET / HOMOMORPHIC HASH (MuHash): Order-Independent Set Fingerprint")
    print("   Unlike Merkle Trees, items can arrive in ANY order, and deletion is O(1).")
    set1 = SimpleMultisetHash()
    set1.add("tx_A")
    set1.add("tx_B")
    set1.add("tx_C")

    # Insert same items in reverse order into set2
    set2 = SimpleMultisetHash()
    set2.add("tx_C")
    set2.add("tx_B")
    set2.add("tx_A")

    print(f"   Set 1 Digest (A, B, C): {set1.digest()[:24]}...")
    print(f"   Set 2 Digest (C, B, A): {set2.digest()[:24]}...")
    print(f"   Digests Match despite different insertion orders: {set1.digest() == set2.digest()} ✓")

    # Demonstrate O(1) dynamic deletion
    print("   Removing 'tx_B' from Set 1 dynamically...")
    set1.remove("tx_B")

    set3 = SimpleMultisetHash()
    set3.add("tx_A")
    set3.add("tx_C")
    print(f"   Set 1 after removal equals fresh Set(A, C): {set1.digest() == set3.digest()} ✓")


if __name__ == "__main__":
    run_comparison_demo()
