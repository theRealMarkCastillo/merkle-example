"""
Use Case 3: P2P File Sharing & Stream Verification (BitTorrent / IPFS Pattern)

THE PROBLEM:
When downloading a large 10 GB file from hundreds of untrusted peers in a P2P network:
- If a peer sends a corrupted or malicious chunk, how do you verify that chunk immediately
  upon arrival?
- Without Merkle Trees:
  - Option A: Hash the entire file at the end. If verification fails, you must throw away
    the whole 10 GB because you don't know which peer sent the bad chunk!
  - Option B: Put one hash per piece in the metadata. This is what BitTorrent v1 does
    (the "pieces" field), and it makes .torrent files grow with the file size.
    BitTorrent v2 (BEP 52) switched to a per-file Merkle tree for this reason.

THE MERKLE SOLUTION:
- The torrent file / magnet link only needs the 32-byte Merkle root (and chunk count).
- When an untrusted peer sends chunk #42, they also send its Merkle proof (log2(N) hashes).
- The client verifies chunk #42 BEFORE writing it to disk. The proof is bound to
  position 42, so a genuine chunk from elsewhere in the file can't be passed off as #42.
- If corrupt: The chunk is immediately discarded, the peer is blacklisted, and the chunk
  is re-requested from an honest peer.
- If valid: Marked as verified.
"""

from __future__ import annotations
from typing import Dict, List, Set
from merkle_tree import MerkleTree, MerkleProof


class P2PFileDownloader:
    """
    Downloads a chunked file from peers, validating every chunk independently
    against a single trusted Merkle Root.
    """

    def __init__(self, filename: str, expected_merkle_root: str, total_chunks: int):
        self.filename = filename
        self.expected_root = expected_merkle_root
        self.total_chunks = total_chunks
        self.downloaded_chunks: Dict[int, bytes] = {}
        self.banned_peers: Set[str] = set()

    def receive_chunk(
        self,
        peer_id: str,
        chunk_index: int,
        chunk_data: bytes,
        proof_path: List[str],
    ) -> bool:
        """
        Validates chunk with its Merkle proof. Rejects and bans peer if invalid.
        """
        if peer_id in self.banned_peers:
            print(f"  [Ignored] Request from banned peer {peer_id}")
            return False

        # Verify chunk using Merkle proof, bound to this exact chunk position
        proof = MerkleProof(
            leaf_data=chunk_data,
            leaf_index=chunk_index,
            tree_size=self.total_chunks,
            path=proof_path,
            expected_root=self.expected_root,
        )

        if proof.verify(verbose=False):
            self.downloaded_chunks[chunk_index] = chunk_data
            print(
                f"  [Chunk #{chunk_index} ACCEPTED] Validated against Merkle Root from peer {peer_id}"
            )
            return True
        else:
            print(
                f"  [Chunk #{chunk_index} REJECTED] CORRUPTED/TAMPERED chunk detected from peer {peer_id}!"
            )
            print(f"  [Security Alert] BANNING peer {peer_id} immediately!")
            self.banned_peers.add(peer_id)
            return False

    def is_complete(self) -> bool:
        return len(self.downloaded_chunks) == self.total_chunks

    def assemble_file(self) -> bytes:
        assert self.is_complete()
        return b"".join(self.downloaded_chunks[i] for i in range(self.total_chunks))


def run_p2p_chunk_use_case():
    print("=" * 72)
    print(" USE CASE 3: P2P File Sharing & Chunk Verification (BitTorrent/IPFS)")
    print("=" * 72)

    # 1. Author prepares a file and creates a Merkle Tree
    raw_file_content = (
        b"BitTorrent Merkle Trees allow peers to verify chunks immediately. "
        b"IPFS (InterPlanetary File System) uses Merkle DAGs for content addressing. "
        b"Even if a malicious peer modifies a single byte, the Merkle root mismatch "
        b"catches the bad actor in real time!"
    )
    chunk_size = 32  # Small chunks for demo purposes
    chunks = [
        raw_file_content[i : i + chunk_size]
        for i in range(0, len(raw_file_content), chunk_size)
    ]
    tree = MerkleTree(chunks)

    print(f"\n1. Original file size: {len(raw_file_content)} bytes ({len(chunks)} chunks).")
    print("   Torrent / Magnet link only publishes the Merkle Root (and chunk count):")
    print(f"   Root: {tree.root}")

    # 2. Downloader initializes client with only the Root
    print("\n2. Downloader starts downloading chunks from untrusted peers...")
    downloader = P2PFileDownloader(
        filename="distributed_spec.txt",
        expected_merkle_root=tree.root,
        total_chunks=len(chunks),
    )

    # 3. Simulate peers serving chunks
    honest_peer_1 = "Peer-Frankfurt-1"
    honest_peer_2 = "Peer-Tokyo-2"
    malicious_peer = "Malicious-Peer-Mallory"
    sneaky_peer = "Sneaky-Peer-Trudy"

    # Peer 1 sends chunk 0
    downloader.receive_chunk(honest_peer_1, 0, chunks[0], tree.get_proof(0).path)

    # Peer 2 sends chunk 1
    downloader.receive_chunk(honest_peer_2, 1, chunks[1], tree.get_proof(1).path)

    # Malicious peer tries to inject corrupt/poisoned chunk 2
    corrupt_chunk_2 = b"MALICIOUS_POISON_DATA_INJECTED!"
    print("\n3. Malicious peer attempts to inject modified chunk #2:")
    downloader.receive_chunk(malicious_peer, 2, corrupt_chunk_2, tree.get_proof(2).path)

    # Sneaky peer sends a GENUINE chunk + proof, but for the wrong position
    print("\n4. Sneaky peer sends genuine chunk #5 (with its valid proof) labelled as chunk #3:")
    downloader.receive_chunk(sneaky_peer, 3, chunks[5], tree.get_proof(5).path)

    # Downloader re-requests chunk 2 from honest peer
    print("\n5. Client re-requests chunk #2 from honest peer:")
    downloader.receive_chunk(honest_peer_1, 2, chunks[2], tree.get_proof(2).path)

    # Download remaining chunks from honest peers
    print("\n6. Downloading remaining chunks...")
    for idx in range(3, len(chunks)):
        peer = honest_peer_1 if idx % 2 == 0 else honest_peer_2
        downloader.receive_chunk(peer, idx, chunks[idx], tree.get_proof(idx).path)

    # 7. Verify full reconstruction
    print(f"\n7. Download complete: {downloader.is_complete()}")
    assembled = downloader.assemble_file()
    print(f"   Reconstructed file matches original: {assembled == raw_file_content} ✓")
    print(f"   Banned peers: {sorted(downloader.banned_peers)}")


if __name__ == "__main__":
    run_p2p_chunk_use_case()
