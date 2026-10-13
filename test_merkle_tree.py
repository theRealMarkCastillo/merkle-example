"""
Unit tests for the Merkle Hash Tree implementation, the use cases, and the
competing data structures. Includes a regression test for each bug found in review.
"""

import contextlib
import io
import unittest
from merkle_tree import MerkleTree, MerkleProof, hash_leaf, hash_children


def quietly(fn, *args, **kwargs):
    """Runs fn while discarding anything it prints (keeps test output clean)."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def reference_mth(leaves):
    """Independent recursive Merkle Tree Hash from RFC 6962 section 2.1."""
    if len(leaves) == 1:
        return hash_leaf(leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hash_children(reference_mth(leaves[:k]), reference_mth(leaves[k:]))


class TestMerkleTree(unittest.TestCase):

    def test_single_element_tree(self):
        tree = MerkleTree(["Single item"])
        self.assertEqual(tree.root, hash_leaf("Single item"))

        proof = tree.get_proof(0)
        self.assertEqual(len(proof.path), 0)
        self.assertTrue(proof.verify())

        # Tampered single element
        tampered_proof = MerkleProof("Tampered", 0, 1, proof.path, tree.root)
        self.assertFalse(tampered_proof.verify())

    def test_two_element_tree(self):
        items = ["Item A", "Item B"]
        tree = MerkleTree(items)
        expected_root = hash_children(hash_leaf("Item A"), hash_leaf("Item B"))
        self.assertEqual(tree.root, expected_root)

        for i in range(len(items)):
            proof = tree.get_proof(i)
            self.assertEqual(len(proof.path), 1)
            self.assertTrue(proof.verify())

    def test_all_proofs_verify_for_many_sizes(self):
        for n in range(1, 40):
            items = [f"Item {i}" for i in range(n)]
            tree = MerkleTree(items)
            for i in range(n):
                self.assertTrue(
                    tree.get_proof(i).verify(),
                    f"Proof verification failed for item {i} in tree of size {n}",
                )

    def test_matches_rfc6962_reference_implementation(self):
        for n in range(1, 70):
            items = [f"x{i}" for i in range(n)]
            self.assertEqual(MerkleTree(items).root, reference_mth(items), f"size {n}")

    def test_rfc6962_certificate_transparency_vectors(self):
        """Known-answer roots from the Certificate Transparency reference test data."""
        leaves = [bytes.fromhex(h) for h in [
            "", "00", "10", "2021", "3031", "40414243",
            "5051525354555657", "606162636465666768696a6b6c6d6e6f"]]
        expected = {
            1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        }
        for n, root in expected.items():
            self.assertEqual(MerkleTree(leaves[:n]).root, root, f"size {n}")

    def test_tampered_leaf_fails(self):
        items = ["A", "B", "C", "D"]
        tree = MerkleTree(items)
        proof = tree.get_proof(2)  # Leaf "C"

        tampered_proof = MerkleProof(
            leaf_data="C_TAMPERED",
            leaf_index=2,
            tree_size=4,
            path=proof.path,
            expected_root=tree.root,
        )
        self.assertFalse(tampered_proof.verify())

    def test_tampered_sibling_hash_fails(self):
        items = ["A", "B", "C", "D"]
        tree = MerkleTree(items)
        proof = tree.get_proof(1)

        tampered_path = list(proof.path)
        # Corrupt the first sibling hash
        tampered_path[0] = "f" * 64

        tampered_proof = MerkleProof(items[1], 1, 4, tampered_path, tree.root)
        self.assertFalse(tampered_proof.verify())

    def test_fake_root_fails(self):
        items = ["A", "B", "C", "D"]
        tree = MerkleTree(items)
        proof = tree.get_proof(0)

        fake_proof = MerkleProof(items[0], 0, 4, proof.path, "1234567890abcdef" * 4)
        self.assertFalse(fake_proof.verify())

    def test_wrong_path_length_fails(self):
        tree = MerkleTree(["A", "B", "C", "D"])
        proof = tree.get_proof(0)
        self.assertFalse(MerkleProof("A", 0, 4, proof.path + ["0" * 64], tree.root).verify())
        self.assertFalse(MerkleProof("A", 0, 4, proof.path[:1], tree.root).verify())

    def test_empty_dataset_raises_error(self):
        with self.assertRaises(ValueError):
            MerkleTree([])
        with self.assertRaises(ValueError):
            _ = MerkleTree().root

    def test_out_of_bounds_index_raises_error(self):
        tree = MerkleTree(["A", "B"])
        with self.assertRaises(IndexError):
            tree.get_proof(-1)
        with self.assertRaises(IndexError):
            tree.get_proof(2)

    def test_domain_separation_rfc6962(self):
        """
        Ensures a leaf hash and an internal node hash with identical payloads
        produce different hashes due to domain separation prefixes (0x00 vs 0x01).
        """
        payload = b"test_payload"
        # Leaf uses 0x00 prefix
        leaf_h = hash_leaf(payload)

        # Internal node uses 0x01 prefix with 32-byte arguments
        chunk1 = payload[:6].ljust(32, b"\x00").hex()
        chunk2 = payload[6:].ljust(32, b"\x00").hex()
        node_h = hash_children(chunk1, chunk2)

        self.assertNotEqual(leaf_h, node_h)

    # --- Regression tests for review findings -------------------------------

    def test_regression_no_duplicate_last_node_collision(self):
        """Bug 1 (CVE-2012-2459 pattern): [A,B,C] and [A,B,C,C] must not share a root."""
        self.assertNotEqual(MerkleTree(["A", "B", "C"]).root, MerkleTree(["A", "B", "C", "C"]).root)
        for n in range(1, 20):
            items = [f"x{i}" for i in range(n)]
            self.assertNotEqual(MerkleTree(items).root, MerkleTree(items + [items[-1]]).root)

    def test_regression_proof_bound_to_index(self):
        """Bug 2: a genuine proof must not verify at any other index."""
        for n in range(2, 17):
            items = [f"x{i}" for i in range(n)]
            tree = MerkleTree(items)
            for i in range(n):
                proof = tree.get_proof(i)
                for j in range(n):
                    if j != i:
                        moved = MerkleProof(items[i], j, n, proof.path, tree.root)
                        self.assertFalse(moved.verify(), f"proof {i} accepted at {j} (n={n})")

    def test_regression_proof_bound_to_tree_size(self):
        """Bug 2 (variant): claiming a different tree size must fail."""
        tree = MerkleTree([f"x{i}" for i in range(6)])
        proof = tree.get_proof(5)
        for wrong_size in (5, 7, 8):
            self.assertFalse(MerkleProof("x5", 5, wrong_size, proof.path, tree.root).verify())

    # --- Use cases ------------------------------------------------------------

    def test_airdrop_use_case(self):
        from use_case_airdrop_whitelist import MockSmartContract, airdrop_leaf

        whitelist = [("0xAlice", 100), ("0xBob", 200), ("0xCarol", 300)]
        tree = MerkleTree([airdrop_leaf(addr, amt) for addr, amt in whitelist])
        contract = MockSmartContract(merkle_root=tree.root, leaf_count=tree.size)

        proof_0 = tree.get_proof(0).path
        self.assertTrue(quietly(contract.claim_airdrop, 0, "0xAlice", 100, proof_0))
        # Double spend
        self.assertFalse(quietly(contract.claim_airdrop, 0, "0xAlice", 100, proof_0))
        # Tampered amount
        self.assertFalse(quietly(contract.claim_airdrop, 1, "0xBob", 9999, tree.get_proof(1).path))
        # Genuine proof at the wrong index
        self.assertFalse(quietly(contract.claim_airdrop, 2, "0xBob", 200, tree.get_proof(1).path))

    def test_airdrop_leaf_encoding_is_unambiguous(self):
        from use_case_airdrop_whitelist import airdrop_leaf

        self.assertNotEqual(airdrop_leaf("a:1", 2), airdrop_leaf("a", "1:2"))

    def test_db_anti_entropy_update(self):
        from use_case_db_anti_entropy import DatabaseReplica, compare_merkle_nodes, repair_replicas

        node_a, node_b = DatabaseReplica("A"), DatabaseReplica("B")
        for i in range(16):
            node_a.put(f"key_{i}", f"val_{i}", version=1)
            node_b.put(f"key_{i}", f"val_{i}", version=1)

        self.assertEqual(compare_merkle_nodes(node_a, node_b).divergent_keys, [])

        # Inject drift
        node_a.put("key_5", "val_5_updated", version=2)
        node_a.rebuild_merkle_tree()
        self.assertEqual(compare_merkle_nodes(node_a, node_b).divergent_keys, ["key_5"])

        # Repair
        quietly(repair_replicas, node_a, node_b, ["key_5"])
        self.assertEqual(node_a.get_merkle_root(), node_b.get_merkle_root())
        self.assertEqual(node_b.storage["key_5"], ("val_5_updated", 2))

    def test_regression_db_anti_entropy_insert(self):
        """Bug 3: inserting one key must report one divergent key, not the whole tail."""
        from use_case_db_anti_entropy import DatabaseReplica, compare_merkle_nodes, repair_replicas

        node_a, node_b = DatabaseReplica("A"), DatabaseReplica("B")
        for i in range(256):
            node_a.put(f"k{i:03d}", "v", 1)
            node_b.put(f"k{i:03d}", "v", 1)
        node_a.put("k000a", "new", 1)  # sorts near the front
        node_a.rebuild_merkle_tree()
        node_b.rebuild_merkle_tree()

        report = compare_merkle_nodes(node_a, node_b)
        self.assertEqual(report.divergent_keys, ["k000a"])
        self.assertEqual(len(report.divergent_buckets), 1)
        self.assertLess(report.rows_exchanged, 2 * 256 // 4)

        quietly(repair_replicas, node_a, node_b, report.divergent_keys)
        self.assertEqual(node_a.get_merkle_root(), node_b.get_merkle_root())

    def test_p2p_chunk_use_case(self):
        from use_case_p2p_chunk_verification import P2PFileDownloader

        chunks = [b"chunk_0", b"chunk_1", b"chunk_2"]
        tree = MerkleTree(chunks)
        dl = P2PFileDownloader("test.bin", tree.root, len(chunks))

        # Honest chunk
        self.assertTrue(quietly(dl.receive_chunk, "P1", 0, chunks[0], tree.get_proof(0).path))
        # Tampered chunk
        self.assertFalse(quietly(dl.receive_chunk, "P_Bad", 1, b"corrupt", tree.get_proof(1).path))
        self.assertIn("P_Bad", dl.banned_peers)

    def test_regression_p2p_chunk_swap_rejected(self):
        """Bug 2 in context: a genuine chunk + proof labelled with the wrong index."""
        from use_case_p2p_chunk_verification import P2PFileDownloader

        chunks = [f"chunk{i}".encode() for i in range(8)]
        tree = MerkleTree(chunks)
        dl = P2PFileDownloader("f", tree.root, 8)
        self.assertFalse(quietly(dl.receive_chunk, "Evil", 5, chunks[3], tree.get_proof(3).path))
        self.assertNotIn(5, dl.downloaded_chunks)

    # --- Competing structures --------------------------------------------------

    def test_smt_membership_and_non_membership(self):
        from competing_methods_comparison import SimpleSparseMerkleTree as SMT

        smt = SMT()
        smt.update("user_1", "active")
        smt.update("user_2", "inactive")
        root = smt.get_root()

        proof = smt.get_proof("user_1")
        self.assertTrue(SMT.verify_membership(proof, root))
        self.assertFalse(SMT.verify_non_membership(proof, root))
        self.assertEqual(proof.leaf_value, "active")

        missing = smt.get_proof("non_existent_user")
        self.assertIsNone(missing.leaf_key)
        self.assertTrue(SMT.verify_non_membership(missing, root))
        self.assertFalse(SMT.verify_membership(missing, root))

    def test_smt_root_independent_of_insertion_order(self):
        from competing_methods_comparison import SimpleSparseMerkleTree as SMT

        a, b = SMT(), SMT()
        for k in ("x", "y", "z"):
            a.update(k, k.upper())
        for k in ("z", "x", "y"):
            b.update(k, k.upper())
        self.assertEqual(a.get_root(), b.get_root())

    def test_regression_smt_proofs_cannot_be_forged(self):
        """Bugs 4 & 5: replayed or hand-crafted SMT proofs must be rejected."""
        from competing_methods_comparison import SimpleSparseMerkleTree as SMT, SMTProof

        smt = SMT()
        smt.update("alice", "x")
        root = smt.get_root()
        alice = smt.get_proof("alice")

        # Alice's proof replayed for other keys
        for other in ("bob", "user15", "mallory"):
            replay = SMTProof(other, alice.leaf_key, alice.leaf_value, alice.siblings)
            self.assertFalse(SMT.verify_membership(replay, root))
            self.assertFalse(SMT.verify_non_membership(replay, root))
            self.assertFalse(
                SMT.verify_membership(SMTProof(other, other, "x", alice.siblings), root)
            )

        # Hiding Alice by claiming her slot is empty
        self.assertFalse(SMT.verify_non_membership(SMTProof("alice", None, None, alice.siblings), root))
        # Lying about Alice's value
        self.assertFalse(SMT.verify_membership(SMTProof("alice", "alice", "y", alice.siblings), root))
        # Truncated proof
        self.assertFalse(SMT.verify_membership(SMTProof("alice", "alice", "x", alice.siblings[:-1]), root))

    def test_bloom_filter(self):
        from competing_methods_comparison import SimpleBloomFilter

        bf = SimpleBloomFilter(256, 3)
        bf.add("apple")
        self.assertTrue(bf.contains("apple"))
        # Deterministic for this input (SHA-256 seeded), not a general guarantee
        self.assertFalse(bf.contains("banana"))

    def test_multiset_hash(self):
        from competing_methods_comparison import SimpleMultisetHash

        m1 = SimpleMultisetHash()
        m1.add("x")
        m1.add("y")

        m2 = SimpleMultisetHash()
        m2.add("y")
        m2.add("x")
        self.assertEqual(m1.digest(), m2.digest())

        m1.remove("x")
        m3 = SimpleMultisetHash()
        m3.add("y")
        self.assertEqual(m1.digest(), m3.digest())
        self.assertNotEqual(m3.digest(), SimpleMultisetHash().digest())


if __name__ == "__main__":
    unittest.main()
