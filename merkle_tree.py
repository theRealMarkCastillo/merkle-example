"""
A complete, educational implementation of a Merkle Hash Tree in Python.

Key Concepts:
- Leaf Nodes: Cryptographic hashes of raw input data chunks.
- Internal Nodes: Cryptographic hashes formed by concatenating pairs of child hashes.
- Merkle Root: The top-most hash that uniquely summarizes the entire data set.
- Audit Proof (Path): A logarithmic-sized (O(log N)) list of sibling hashes
  required to prove inclusion of a specific leaf without revealing or hashing the entire dataset.
- Domain Separation (RFC 6962): Prepends 0x00 to leaf hashes and 0x01 to internal nodes
  to protect against second-preimage attacks.
- Tree Shape (RFC 6962): When a level has an odd number of nodes, the last node is
  promoted unchanged to the next level. It is NOT duplicated: duplication lets two
  different lists ([A,B,C] and [A,B,C,C]) share a root (Bitcoin's CVE-2012-2459).
- Position Binding: The verifier derives each sibling's side (left/right) from the
  leaf's index and the tree size, so a proof only verifies for one exact position.
"""

from __future__ import annotations
import hashlib
from typing import List, Optional


def sha256(data: bytes) -> str:
    """Returns the hexadecimal SHA-256 digest of input bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_leaf(data: bytes | str) -> str:
    """
    Hashes leaf data with domain separation prefix (0x00).
    Domain separation prevents second-preimage attacks where an internal node
    could be spoofed as a leaf.
    """
    raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
    return sha256(b"\x00" + raw_bytes)


def hash_children(left_hash: str, right_hash: str) -> str:
    """
    Hashes two child hashes together with domain separation prefix (0x01).
    """
    combined = b"\x01" + bytes.fromhex(left_hash) + bytes.fromhex(right_hash)
    return sha256(combined)


def proof_directions(leaf_index: int, tree_size: int) -> List[str]:
    """
    Derives which side each proof sibling is on, from the leaf's position alone.

    Walks up the tree using the same pairing rule as MerkleTree.build:
      - odd index                          -> node is a right child, sibling is on the 'left'
      - even index with a right neighbour  -> sibling is on the 'right'
      - even index, last node of an odd-sized level
                                           -> node is promoted unchanged, no sibling here

    Because the verifier computes this itself (instead of trusting directions sent
    by the prover), a proof only verifies for one specific (leaf_index, tree_size).
    """
    if tree_size < 1 or not 0 <= leaf_index < tree_size:
        raise IndexError(f"leaf_index {leaf_index} is not valid for a tree of size {tree_size}")

    directions: List[str] = []
    idx, level_size = leaf_index, tree_size
    while level_size > 1:
        if idx % 2 == 1:
            directions.append("left")
        elif idx + 1 < level_size:
            directions.append("right")
        # else: promoted to the next level without a sibling
        idx //= 2
        level_size = (level_size + 1) // 2
    return directions


class MerkleProof:
    """
    Represents an audit path (Merkle Proof) for verifying membership of a leaf.

    Attributes:
        leaf_data: The original data chunk being verified.
        leaf_index: The index of the leaf in the original tree. The verifier uses it
                    to work out which side each sibling is on.
        tree_size: The number of leaves in the tree the proof was generated from.
        path: Sibling hashes ordered from the leaf up to the root. Directions are
              deliberately NOT included; they are derived from leaf_index/tree_size.
        expected_root: The expected Merkle root hash.
    """

    def __init__(
        self,
        leaf_data: bytes | str,
        leaf_index: int,
        tree_size: int,
        path: List[str],
        expected_root: str,
    ):
        self.leaf_data = leaf_data
        self.leaf_index = leaf_index
        self.tree_size = tree_size
        self.path = path
        self.expected_root = expected_root

    @property
    def directions(self) -> List[str]:
        """Sibling sides derived from the leaf position (for display/inspection)."""
        return proof_directions(self.leaf_index, self.tree_size)

    def verify(self, verbose: bool = False) -> bool:
        """
        Reconstructs the Merkle Root from leaf_data and the sibling path,
        then checks if it matches the expected Merkle Root.
        """
        try:
            directions = proof_directions(self.leaf_index, self.tree_size)
        except IndexError as exc:
            if verbose:
                print(f"  Rejected: {exc}")
            return False

        if len(directions) != len(self.path):
            if verbose:
                print(
                    f"  Rejected: index {self.leaf_index} in a tree of {self.tree_size} needs "
                    f"{len(directions)} sibling hashes, proof has {len(self.path)}"
                )
            return False

        current_hash = hash_leaf(self.leaf_data)
        if verbose:
            leaf_display = (
                self.leaf_data
                if isinstance(self.leaf_data, str)
                else self.leaf_data.hex()
            )
            print(f"  [Proof Step 0] Leaf Data: {leaf_display!r}")
            print(f"                 Leaf Hash: {current_hash[:16]}...")

        for step_num, (sibling_hash, direction) in enumerate(
            zip(self.path, directions), start=1
        ):
            prev_hash = current_hash
            if direction == "left":
                # Sibling was on the left, current node is on the right
                current_hash = hash_children(sibling_hash, prev_hash)
                if verbose:
                    print(
                        f"  [Proof Step {step_num}] Sibling (Left):  {sibling_hash[:16]}... "
                        f"+ Current (Right): {prev_hash[:16]}... -> {current_hash[:16]}..."
                    )
            else:
                # Current node is on the left, sibling is on the right
                current_hash = hash_children(prev_hash, sibling_hash)
                if verbose:
                    print(
                        f"  [Proof Step {step_num}] Current (Left): {prev_hash[:16]}... "
                        f"+ Sibling (Right): {sibling_hash[:16]}... -> {current_hash[:16]}..."
                    )

        matches = current_hash == self.expected_root
        if verbose:
            print(f"  Recomputed Root: {current_hash}")
            print(f"  Expected Root:   {self.expected_root}")
            print(f"  Status:          {'VALID ✓' if matches else 'INVALID ✗'}")

        return matches


class MerkleTree:
    """
    A binary Merkle Hash Tree constructed from a sequence of data items.

    Attributes:
        raw_data: List of raw items used to build the tree.
        levels: List of tree levels from leaves (level 0) up to the root (last level).
    """

    def __init__(self, data_items: Optional[List[bytes | str]] = None):
        self.raw_data: List[bytes | str] = []
        self.levels: List[List[str]] = []
        if data_items is not None:
            self.build(data_items)

    @property
    def root(self) -> str:
        """Returns the Merkle root hash. Raises ValueError if the tree is empty."""
        if not self.levels:
            raise ValueError("Tree is empty")
        return self.levels[-1][0]

    @property
    def size(self) -> int:
        """Number of leaves in the tree."""
        return len(self.raw_data)

    def build(self, data_items: List[bytes | str]) -> None:
        """
        Builds the Merkle tree from the provided list of data items.
        If an odd number of nodes exists at any level, the last node is promoted
        unchanged to the next level (RFC 6962 tree shape).
        """
        if not data_items:
            raise ValueError("Cannot build a Merkle Tree with empty data items")

        self.raw_data = list(data_items)

        # Level 0: Hash the raw data leaves
        current_hashes: List[str] = [hash_leaf(item) for item in self.raw_data]
        self.levels = [current_hashes]

        # Iteratively build parent levels until only the root remains
        while len(current_hashes) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_hashes) - 1, 2):
                next_level.append(hash_children(current_hashes[i], current_hashes[i + 1]))

            # Odd count: promote the last node unchanged. Do NOT duplicate it —
            # duplication makes [A,B,C] and [A,B,C,C] share a root (CVE-2012-2459).
            if len(current_hashes) % 2 == 1:
                next_level.append(current_hashes[-1])

            self.levels.append(next_level)
            current_hashes = next_level

    def get_proof(self, index: int) -> MerkleProof:
        """
        Generates an audit proof for the leaf at the given index.

        Args:
            index: The 0-based index of the leaf item.

        Returns:
            A MerkleProof object containing the audit path and expected root.
        """
        if not self.levels:
            raise ValueError("Tree is empty")
        if index < 0 or index >= len(self.raw_data):
            raise IndexError(f"Index {index} out of bounds (0..{len(self.raw_data)-1})")

        proof_path: List[str] = []
        current_idx = index

        # Walk up from leaves to the level below root
        for level in self.levels[:-1]:
            if current_idx % 2 == 1:
                # current is right child, sibling is left child
                proof_path.append(level[current_idx - 1])
            elif current_idx + 1 < len(level):
                # current is left child, sibling is right child
                proof_path.append(level[current_idx + 1])
            # else: last node of an odd-sized level, promoted with no sibling
            current_idx //= 2

        return MerkleProof(
            leaf_data=self.raw_data[index],
            leaf_index=index,
            tree_size=self.size,
            path=proof_path,
            expected_root=self.root,
        )

    def print_tree(self) -> None:
        """Prints a human-readable visual diagram of the tree levels."""
        if not self.levels:
            print("Tree is empty.")
            return

        print("\n" + "=" * 68)
        print("                      MERKLE TREE STRUCTURE")
        print("=" * 68)
        for depth_from_root, level in enumerate(reversed(self.levels)):
            level_num = len(self.levels) - 1 - depth_from_root
            label = "Root" if level_num == len(self.levels) - 1 else f"Level {level_num}"
            print(f"\n[{label}] ({len(level)} node{'s' if len(level) > 1 else ''}):")
            for i, h in enumerate(level):
                if level_num == 0 and i < len(self.raw_data):
                    data_preview = repr(self.raw_data[i])
                    print(f"  [{i}] {h[:16]}... (data: {data_preview})")
                else:
                    print(f"  [{i}] {h[:16]}...")
        print("=" * 68 + "\n")


def run_demo() -> None:
    """Interactive demo illustrating Merkle tree operations."""
    print("====================================================================")
    print("             Merkle Hash Tree Demonstration in Python               ")
    print("====================================================================")

    # 1. Sample transactions
    transactions = [
        "Tx1: Alice -> Bob 10 BTC",
        "Tx2: Bob -> Charlie 5 BTC",
        "Tx3: Charlie -> Dave 2 BTC",
        "Tx4: Dave -> Eve 1 BTC",
    ]

    print("\n1. Building Merkle Tree from 4 transactions:")
    for tx in transactions:
        print(f"   - {tx}")

    tree = MerkleTree(transactions)
    tree.print_tree()

    print(f"Merkle Root: {tree.root}\n")

    # 2. Generate and verify a valid proof
    target_idx = 1
    target_tx = transactions[target_idx]
    print(f"2. Generating Merkle Audit Proof for index {target_idx}: {target_tx!r}")
    proof = tree.get_proof(target_idx)
    print(f"   Proof path length: {len(proof.path)} sibling hashes (log2(4) = 2)")
    for i, (sibling_hash, direction) in enumerate(zip(proof.path, proof.directions)):
        print(f"   - Step {i+1}: Sibling {sibling_hash[:16]}... on {direction.upper()}")
    print("   (Sides are derived by the verifier from index + tree size, not sent by the prover.)")

    print("\n3. Verifying the Audit Proof:")
    is_valid = proof.verify(verbose=True)
    print(f"   Result: {'Verified successfully!' if is_valid else 'Verification failed!'}")

    # 3. Demonstrate tamper detection
    print("\n4. Tamper Resistance Test #1: Tampering with the transaction data")
    tampered_tx = "Tx2: Bob -> Mallory 500 BTC"
    print(f"   Original data: {target_tx!r}")
    print(f"   Tampered data: {tampered_tx!r}")
    tampered_proof = MerkleProof(
        leaf_data=tampered_tx,
        leaf_index=target_idx,
        tree_size=tree.size,
        path=proof.path,
        expected_root=tree.root,
    )
    tampered_valid = tampered_proof.verify(verbose=True)
    print(f"   Result: {'ACCEPTED (Unexpected!)' if tampered_valid else 'REJECTED ✓ (Tampering detected!)'}")

    # 4. Demonstrate tamper detection with fake root
    print("\n5. Tamper Resistance Test #2: Verifying against a fake Merkle Root")
    fake_root = "0" * 64
    fake_root_proof = MerkleProof(
        leaf_data=target_tx,
        leaf_index=target_idx,
        tree_size=tree.size,
        path=proof.path,
        expected_root=fake_root,
    )
    fake_root_valid = fake_root_proof.verify(verbose=False)
    print(f"   Fake Root: {fake_root}")
    print(f"   Result: {'ACCEPTED (Unexpected!)' if fake_root_valid else 'REJECTED ✓ (Root mismatch detected!)'}")

    # 5. Position binding: a genuine proof claimed for a different position
    print("\n6. Position Binding Test: genuine data + proof, but claimed at index 2")
    moved_proof = MerkleProof(
        leaf_data=target_tx,
        leaf_index=2,
        tree_size=tree.size,
        path=proof.path,
        expected_root=tree.root,
    )
    moved_valid = moved_proof.verify(verbose=False)
    print(f"   Result: {'ACCEPTED (Unexpected!)' if moved_valid else 'REJECTED ✓ (Proof only valid at index 1)'}")

    # 6. Odd number of leaves example
    print("\n7. Handling Odd Number of Leaves (5 transactions):")
    odd_transactions = transactions + ["Tx5: Eve -> Frank 0.5 BTC"]
    odd_tree = MerkleTree(odd_transactions)
    odd_tree.print_tree()
    print(f"Odd Tree Root: {odd_tree.root}")
    print("(Tx5's hash has no partner, so it is promoted unchanged up the levels.)")

    odd_proof = odd_tree.get_proof(4)  # Proof for Tx5
    print(f"\nProof for Tx5 (promoted node, only {len(odd_proof.path)} sibling):")
    odd_proof_valid = odd_proof.verify(verbose=True)
    print(f"Result: {'Verified successfully!' if odd_proof_valid else 'Verification failed!'}")

    # 7. Why we promote instead of duplicating
    print("\n8. Promotion vs. duplication (CVE-2012-2459):")
    root_abc = MerkleTree(["A", "B", "C"]).root
    root_abcc = MerkleTree(["A", "B", "C", "C"]).root
    print(f"   Root of [A, B, C]:    {root_abc[:24]}...")
    print(f"   Root of [A, B, C, C]: {root_abcc[:24]}...")
    print(f"   Different roots: {root_abc != root_abcc} ✓ (duplicating the odd node would make them equal)")


if __name__ == "__main__":
    run_demo()
