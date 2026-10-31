// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file builds a MERKLE TREE: a way to squeeze a list of thousands of
// transactions into ONE 32-byte fingerprint, called the merkle root. That
// root is stored in the block header (hashMerkleRoot, see
// primitives/block.h), so the small 80-byte header "seals" every transaction
// in the block.
//
// How it works, like a sports tournament bracket:
//   - Start with the hash (txid) of every transaction. These are the
//     "leaves" at the bottom of the tree.
//   - Pair them up: 1 with 2, 3 with 4, and so on. Hash each pair together
//     to get one new hash per pair. That gives a level half as big.
//   - Repeat until only one hash is left. That is the root, the "winner".
//   - Bitcoin's special rule: if a level has an odd number of hashes, the
//     last one is paired with a copy of itself.
// If anyone changes even one transaction, its hash changes, which changes
// every hash above it, all the way up to the root.
//
// Why a tree and not one big hash of everything? Because it lets you prove
// that ONE transaction is in a block by showing only about 12 hashes (one
// per level), instead of the whole block. This is called a "merkle path"
// or "merkle proof", and lightweight wallets on phones rely on it.
//
// The main functions:
//   - ComputeMerkleRoot():      the tournament described above.
//   - BlockMerkleRoot():        the root of a block's transactions (txids).
//   - BlockWitnessMerkleRoot(): a second root using wtxids, for SegWit.
//   - TransactionMerklePath():  the proof that one transaction is in a block.
#include <consensus/merkle.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <util/check.h>

#include <cstddef>
#include <utility>

// COMMENT HOUSE: The original developer comment below is a real security
// story, CVE-2012-2459 ("CVE" is the official ID system for security bugs).
// In short: because of the "copy the odd one out" rule, two DIFFERENT lists
// of transactions can produce the SAME merkle root. The tree drawing shows
// that the list ending in 5,6 and the list ending in 5,6,5,6 both give root
// A. An attacker could send a node the broken (duplicated) version of a real
// block. The node would correctly reject it, but if it then remembered that
// block hash as "bad forever", it would also reject the REAL block, which
// has the same hash. The fix is to detect the duplicate pattern and treat it
// as a broken block, without blaming the block hash itself.
/*     WARNING! If you're reading this because you're learning about crypto
       and/or designing a new system that will use merkle trees, keep in mind
       that the following merkle tree algorithm has a serious flaw related to
       duplicate txids, resulting in a vulnerability (CVE-2012-2459).

       The reason is that if the number of hashes in the list at a given level
       is odd, the last one is duplicated before computing the next level (which
       is unusual in Merkle trees). This results in certain sequences of
       transactions leading to the same merkle root. For example, these two
       trees:

                    A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6

       for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
       6 are repeated) result in the same root hash A (because the hash of both
       of (F) and (F,F) is C).

       The vulnerability results from being able to send a block with such a
       transaction list, with the same merkle root, and the same block hash as
       the original without duplication, resulting in failed validation. If the
       receiving node proceeds to mark that block as permanently invalid
       however, it will fail to accept further unmodified (and thus potentially
       valid) versions of the same block. We defend against this by detecting
       the case where we would hash two identical hashes at the end of the list
       together, and treating that identically to the block having an invalid
       merkle root. Assuming no double-SHA256 collisions, this will detect all
       known ways of changing the transactions without affecting the merkle
       root.
*/
// COMMENT HOUSE: ComputeMerkleRoot() takes the list of leaf hashes and
// returns the root. "mutated" is an optional true/false answer to "did this
// list look like the duplicate trick from CVE-2012-2459?". It is a pointer
// (the *), so the caller can pass nullptr to say "I don't need that answer".
uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    // COMMENT HOUSE: Each trip around this loop climbs one level of the tree,
    // until only the root is left.
    while (hashes.size() > 1) {
        if (mutated) {
            // Check every level because equal pairs can appear above the leaves,
            // as in the [1,2,3,4,5,6,5,6] construction described above.
            // Continuing after finding one is redundant, but mutated blocks should
            // not propagate through the network anyway, and the total number of
            // comparisons is the same as for an unmutated input of the same length.
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;
            }
        }
        // COMMENT HOUSE: "hashes.size() & 1" is true when the count is odd. If so,
        // copy the last hash onto the end, so every hash has a partner.
        if (hashes.size() & 1) {
            hashes.push_back(hashes.back());
        }
        // COMMENT HOUSE: SHA256D64 hashes every pair at once with double SHA-256
        // (64 bytes in, 32 bytes out per pair). It writes the results over the start
        // of the same list to save memory. Then resize() throws away the second half,
        // which is now leftover. The list is now one level up and half as long.
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    if (mutated) *mutated = mutation;
    // COMMENT HOUSE: An empty list has no root, so the answer is all zeros. A real
    // block is never empty, because it always has a coinbase transaction.
    if (hashes.size() == 0) return uint256();
    return hashes[0];
}


// COMMENT HOUSE: BlockMerkleRoot() collects the txid of every transaction in
// the block, in order, and builds the tree from them. This is the value that
// must match hashMerkleRoot in the block header, or the block is invalid.
// reserve() just sets aside memory in advance. It does not change the result.
uint256 BlockMerkleRoot(const CBlock& block, bool* mutated)
{
    std::vector<uint256> leaves;
    leaves.reserve((block.vtx.size() + 1) & ~1ULL); // capacity rounded up to even
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves.push_back(block.vtx[s]->GetHash().ToUint256());
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);
}

// COMMENT HOUSE: BlockWitnessMerkleRoot() builds a SECOND tree, from the
// wtxids (IDs that include signature data, see primitives/transaction.cpp).
// This root is not in the header. Since SegWit, it is stored inside the
// coinbase transaction instead (more in the SegWit phase). The coinbase's own
// leaf is set to all zeros, because the coinbase cannot contain a fingerprint
// of itself.
uint256 BlockWitnessMerkleRoot(const CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.reserve((block.vtx.size() + 1) & ~1ULL); // capacity rounded up to even
    leaves.emplace_back(); // The witness hash of the coinbase is 0.
    for (size_t s = 1; s < block.vtx.size(); s++) {
        leaves.push_back(block.vtx[s]->GetWitnessHash().ToUint256());
    }
    return ComputeMerkleRoot(std::move(leaves));
}

/* This implements a constant-space merkle path calculator, limited to 2^32 leaves. */
// COMMENT HOUSE: MerkleComputation() is an advanced function. You can skip
// it on a first read. It builds the merkle path for the leaf at leaf_pos: the
// list of "partner" hashes, one per level, that someone needs in order to
// climb from that leaf to the root and check it matches.
// It gets the same root as ComputeMerkleRoot(), but uses a clever trick: it
// reads the leaves one at a time and keeps at most one hash per level (the
// inner array), so it uses very little memory. It does this using the binary
// digits of count, much like carrying digits when you add 1 in binary. The
// original developer comments inside explain each step.
// "static" means this function can only be used inside this file.
static void MerkleComputation(const std::vector<uint256>& leaves, uint32_t leaf_pos, std::vector<uint256>& path)
{
    path.clear();
    Assume(leaves.size() <= UINT32_MAX);
    if (leaves.size() == 0) {
        return;
    }
    // count is the number of leaves processed so far.
    uint32_t count = 0;
    // inner is an array of eagerly computed subtree hashes, indexed by tree
    // level (0 being the leaves).
    // For example, when count is 25 (11001 in binary), inner[4] is the hash of
    // the first 16 leaves, inner[3] of the next 8 leaves, and inner[0] equal to
    // the last leaf. The other inner entries are undefined.
    uint256 inner[32];
    // Which position in inner is a hash that depends on the matching leaf.
    int matchlevel = -1;
    // First process all leaves into 'inner' values.
    while (count < leaves.size()) {
        uint256 h = leaves[count];
        bool matchh = count == leaf_pos;
        count++;
        int level;
        // For each of the lower bits in count that are 0, do 1 step. Each
        // corresponds to an inner value that existed before processing the
        // current leaf, and each needs a hash to combine it.
        for (level = 0; !(count & ((uint32_t{1}) << level)); level++) {
            if (matchh) {
                path.push_back(inner[level]);
            } else if (matchlevel == level) {
                path.push_back(h);
                matchh = true;
            }
            h = Hash(inner[level], h);
        }
        // Store the resulting hash at inner position level.
        inner[level] = h;
        if (matchh) {
            matchlevel = level;
        }
    }
    // Do a final 'sweep' over the rightmost branch of the tree to process
    // odd levels, and reduce everything to a single top value.
    // Level is the level (counted from the bottom) up to which we've sweeped.
    int level = 0;
    // As long as bit number level in count is zero, skip it. It means there
    // is nothing left at this level.
    while (!(count & ((uint32_t{1}) << level))) {
        level++;
    }
    uint256 h = inner[level];
    bool matchh = matchlevel == level;
    while (count != ((uint32_t{1}) << level)) {
        // If we reach this point, h is an inner value that is not the top.
        // We combine it with itself (Bitcoin's special rule for odd levels in
        // the tree) to produce a higher level one.
        if (matchh) {
            path.push_back(h);
        }
        h = Hash(h, h);
        // Increment count to the value it would have if two entries at this
        // level had existed.
        count += ((uint32_t{1}) << level);
        level++;
        // And propagate the result upwards accordingly.
        while (!(count & ((uint32_t{1}) << level))) {
            if (matchh) {
                path.push_back(inner[level]);
            } else if (matchlevel == level) {
                path.push_back(h);
                matchh = true;
            }
            h = Hash(inner[level], h);
            level++;
        }
    }
}

static std::vector<uint256> ComputeMerklePath(const std::vector<uint256>& leaves, uint32_t position) {
    std::vector<uint256> ret;
    MerkleComputation(leaves, position, ret);
    return ret;
}

// COMMENT HOUSE: TransactionMerklePath() gives the proof that the
// transaction at "position" is in the block: the partner hashes from the
// bottom of the tree to the top. Position 0 is the coinbase transaction.
std::vector<uint256> TransactionMerklePath(const CBlock& block, uint32_t position)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s]->GetHash().ToUint256();
    }
    return ComputeMerklePath(leaves, position);
}
