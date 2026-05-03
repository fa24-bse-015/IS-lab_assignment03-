"""
IS Lab Assignment
Task 1: Basic Blockchain Implementation
Objective: Understand the core structure of blockchain
"""

import hashlib
import time


class Block:
    """
    Represents a single block in the blockchain.
    Each block stores an index, timestamp, data, the previous block's hash,
    and its own hash computed using SHA-256.
    """

    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """
        Computes the SHA-256 hash of the block's contents.
        All fields are combined into a single string, encoded to bytes,
        then passed through SHA-256 to produce a 64-character hex digest.
        """
        block_contents = (
            str(self.index) +
            str(self.timestamp) +
            str(self.data) +
            str(self.previous_hash)
        )
        return hashlib.sha256(block_contents.encode()).hexdigest()

    def __repr__(self):
        return (
            f"\n{'='*60}\n"
            f"  Block #{self.index}\n"
            f"{'='*60}\n"
            f"  Timestamp    : {self.timestamp}\n"
            f"  Data         : {self.data}\n"
            f"  Previous Hash: {self.previous_hash}\n"
            f"  Hash         : {self.hash}\n"
        )


class Blockchain:
    """
    A chain of Block objects. The first block is the genesis block,
    created automatically with no previous hash.
    """

    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Block #0 with no predecessor — previous_hash set to '0'."""
        genesis = Block(index=0, data="Genesis Block", previous_hash="0")
        self.chain.append(genesis)

    def get_latest_block(self):
        """Returns the most recently added block."""
        return self.chain[-1]

    def add_block(self, data):
        """
        Creates a new block and appends it to the chain.
        The new block's previous_hash is the current tip's hash.
        """
        previous_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=previous_block.hash
        )
        self.chain.append(new_block)
        print(f"  [+] Block #{new_block.index} added successfully.")

    def display_chain(self):
        """Prints every block in the chain."""
        print("\n" + "="*60)
        print("           BLOCKCHAIN — FULL CHAIN VIEW")
        print("="*60)
        for block in self.chain:
            print(block)

    def is_chain_valid(self):
        """
        Validates integrity of the entire blockchain:
        1. Recomputes each block's hash and compares to stored hash.
        2. Checks each block's previous_hash matches the prior block's hash.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                print(f"  [!] Block #{i} hash is invalid — data may have been tampered with.")
                return False

            if current.previous_hash != previous.hash:
                print(f"  [!] Block #{i} previous_hash does not match Block #{i-1} hash.")
                return False

        return True

    def tamper_block(self, index, new_data):
        """
        Simulates tampering: directly changes a block's data without
        updating its hash — breaking chain integrity.
        """
        if 0 < index < len(self.chain):
            print(f"\n  [TAMPER] Changing Block #{index} data to: '{new_data}'")
            self.chain[index].data = new_data



if __name__ == "__main__":
    print("\n" + "#"*60)
    print("#       TASK 1: BASIC BLOCKCHAIN IMPLEMENTATION         #")
    print("#"*60)

    bc = Blockchain()

    print("\n--- Adding blocks to the chain ---")
    bc.add_block("Alice pays Bob 50 coins")
    bc.add_block("Bob pays Carol 20 coins")
    bc.add_block("Carol pays Dave 10 coins")
    bc.add_block("Dave pays Eve 5 coins")

    bc.display_chain()

    print("\n--- Integrity Check (Before Tampering) ---")
    print(f"  Chain valid: {bc.is_chain_valid()}")

    bc.tamper_block(2, "Bob pays Carol 9999 coins")

    print("\n--- Integrity Check (After Tampering) ---")
    print(f"  Chain valid: {bc.is_chain_valid()}")
    print("\n  Explanation: Changing Block #2 data invalidates its hash.")
    print("  All subsequent blocks that reference it are also compromised.")
