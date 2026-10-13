"""
Use Case 1: Smart Contract Whitelist / Token Airdrop (Blockchain Pattern)

THE PROBLEM:
A decentralized protocol wants to distribute tokens to 100,000 eligible users.
- Naive Approach: Store all 100,000 addresses and amounts in smart contract storage.
  Cost: On Ethereum each new storage slot costs ~20,000 gas, so 100,000 entries is
  roughly 2 billion gas — far more than fits in one block. It would have to be spread
  over many transactions, at a cost that depends on gas prices but is typically very large.

THE MERKLE SOLUTION:
- The protocol hashes all (address, amount) pairs into a Merkle Tree off-chain.
- The smart contract stores only the 32-byte `merkle_root` (plus the leaf count).
- When an eligible user claims, they supply their leaf index, `(address, amount)`,
  and a small Merkle audit proof (17 hashes for 100k users = 544 bytes).
- The contract verifies the proof against `merkle_root` in O(log N) time and transfers
  the tokens. Claims are tracked by leaf index, which the proof is bound to.
"""

from __future__ import annotations
import json
from typing import Dict, List, Set
from merkle_tree import MerkleTree, MerkleProof


def airdrop_leaf(account: str, amount: int) -> str:
    """
    Unambiguous leaf encoding. A naive f"{account}:{amount}" lets different
    (account, amount) pairs collide if a field contains ':'; JSON escapes that.
    """
    return json.dumps([account, amount], separators=(",", ":"))


class MockSmartContract:
    """
    Simulates a blockchain smart contract storing only the Merkle root.
    """

    def __init__(self, merkle_root: str, leaf_count: int):
        # The ONLY persistent data the contract stores for whitelist verification!
        self.merkle_root: str = merkle_root
        self.leaf_count: int = leaf_count
        self.claimed: Set[int] = set()
        self.balances: Dict[str, int] = {}

    def claim_airdrop(
        self,
        index: int,
        account: str,
        amount: int,
        proof_path: List[str],
    ) -> bool:
        """
        Executes a claim. If valid, tokens are minted/transferred.
        """
        # 1. Prevent double spending / re-claims
        if index in self.claimed:
            print(f"  [Contract Error] Leaf #{index} ({account}) has already been claimed!")
            return False

        # 2. Recompute and verify the Merkle root on-chain
        proof = MerkleProof(
            leaf_data=airdrop_leaf(account, amount),
            leaf_index=index,
            tree_size=self.leaf_count,
            path=proof_path,
            expected_root=self.merkle_root,
        )

        if not proof.verify(verbose=False):
            print(f"  [Contract Error] Invalid Merkle proof for {account} / {amount} at leaf #{index}!")
            return False

        # 3. Mark as claimed and update balance
        self.claimed.add(index)
        self.balances[account] = self.balances.get(account, 0) + amount
        print(f"  [Contract Success] {account} successfully claimed {amount} tokens!")
        return True


def run_airdrop_use_case():
    print("=" * 72)
    print(" USE CASE 1: Smart Contract Whitelist / Airdrop (Blockchain Pattern)")
    print("=" * 72)

    # 1. Generate eligible user whitelist off-chain
    whitelist = [
        ("0xAlice11111111111111111111111111111111111", 500),
        ("0xBob2222222222222222222222222222222222222", 350),
        ("0xCharlie333333333333333333333333333333333", 200),
        ("0xDave444444444444444444444444444444444444", 150),
        ("0xEve5555555555555555555555555555555555555", 100),
        ("0xFrank66666666666666666666666666666666666", 75),
        ("0xGrace77777777777777777777777777777777777", 50),
        ("0xHeidi88888888888888888888888888888888888", 25),
    ]

    leaves = [airdrop_leaf(addr, amt) for addr, amt in whitelist]
    tree = MerkleTree(leaves)

    print(f"Off-chain: Built Merkle Tree from {len(whitelist)} eligible recipients.")
    print(f"Off-chain Merkle Root: {tree.root}\n")

    # 2. Deploy contract with ONLY the Merkle root
    print("Step 1: Deploying Smart Contract with Merkle Root in storage...")
    contract = MockSmartContract(merkle_root=tree.root, leaf_count=tree.size)
    print("Contract deployed! On-chain storage used: one 32-byte root + leaf count.\n")

    # 3. Legitimate user Alice claims her tokens
    alice_addr, alice_amt = whitelist[0]
    print(f"Step 2: Alice ({alice_addr[:10]}...) generates proof and claims {alice_amt} tokens:")
    alice_proof = tree.get_proof(0)
    print(f"  Proof size: {len(alice_proof.path)} hashes (~{len(alice_proof.path) * 32} bytes)")
    contract.claim_airdrop(0, alice_addr, alice_amt, alice_proof.path)

    # 4. Alice attempts to double-claim
    print("\nStep 3: Alice attempts to claim a second time (Replay Attack):")
    contract.claim_airdrop(0, alice_addr, alice_amt, alice_proof.path)

    # 5. Bob tries to tamper with his amount (claims 9999 instead of 350)
    bob_addr, bob_amt = whitelist[1]
    bob_proof = tree.get_proof(1)
    tampered_amt = 9999
    print(f"\nStep 4: Bob tries to tamper with claim amount ({tampered_amt} instead of {bob_amt}):")
    contract.claim_airdrop(1, bob_addr, tampered_amt, bob_proof.path)

    # 6. Unlisted attacker Mallory tries to claim
    mallory_addr = "0xMallory999999999999999999999999999999999"
    print("\nStep 5: Unlisted user Mallory tries to claim using a forged proof:")
    contract.claim_airdrop(2, mallory_addr, 500, alice_proof.path)

    # 7. Bob claims legitimately
    print(f"\nStep 6: Bob claims with his legitimate amount ({bob_amt}):")
    contract.claim_airdrop(1, bob_addr, bob_amt, bob_proof.path)

    print("\n" + "-" * 72)
    print("Summary of Balances in Contract:")
    for user, bal in contract.balances.items():
        print(f"  {user[:10]}... : {bal} tokens")
    print("-" * 72)


if __name__ == "__main__":
    run_airdrop_use_case()
