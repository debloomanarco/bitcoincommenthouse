// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// The code for the block index ("index cards") and active chain described
// in chain.h. Read chain.h first. The highlights are SetTip(),
// GetAncestor() with its skip-list trick, and GetBitsProof(), which turns
// difficulty into "work".
#include <chain.h>
#include <tinyformat.h>
#include <util/check.h>

std::string CBlockIndex::ToString() const
{
    return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
                     pprev, nHeight, hashMerkleRoot.ToString(), GetBlockHash().ToString());
}

// COMMENT HOUSE: SetTip(): make "block" the new tip of the active chain.
// First the list is resized to the new height. Then, starting at the new
// tip, each entry is filled in, following pprev backwards, until it reaches
// a block that is already in the right place. That block is where the new
// branch joins the old one, so everything below it is already correct.
void CChain::SetTip(CBlockIndex& block)
{
    CBlockIndex* pindex = &block;
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

// COMMENT HOUSE: The block hashes for a CBlockLocator: the 10 or so most
// recent blocks one by one, then steps of 2, 4, 8, 16, ... blocks back,
// always ending with the genesis block. Even for a chain of a million
// blocks, that is only about 30 hashes.
std::vector<uint256> LocatorEntries(const CBlockIndex* index)
{
    int step = 1;
    std::vector<uint256> have;
    if (index == nullptr) return have;

    have.reserve(32);
    while (index) {
        have.emplace_back(index->GetBlockHash());
        if (index->nHeight == 0) break;
        // Exponentially larger steps back, plus the genesis block.
        int height = std::max(index->nHeight - step, 0);
        // Use skiplist.
        index = index->GetAncestor(height);
        if (have.size() > 10) step *= 2;
    }
    return have;
}

CBlockLocator GetLocator(const CBlockIndex* index)
{
    return CBlockLocator{LocatorEntries(index)};
}

// COMMENT HOUSE: FindFork(): the newest block that "index" (which may be on
// another branch) shares with the active chain. First drop down to the
// chain's height, then follow pprev until reaching a block that the active
// chain contains.
const CBlockIndex* CChain::FindFork(const CBlockIndex& index) const
{
    const auto* pindex{&index};
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(*pindex))
        pindex = pindex->pprev;
    return pindex;
}

// COMMENT HOUSE: Finds the first block on the active chain at or after a given
// time and height. std::lower_bound searches a sorted list by repeatedly
// halving it, like looking up a word in a dictionary, instead of checking
// every block.
CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime, int height) const
{
    std::pair<int64_t, int> blockparams = std::make_pair(nTime, height);
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), blockparams,
        [](CBlockIndex* pBlock, const std::pair<int64_t, int>& blockparams) -> bool { return pBlock->GetBlockTimeMax() < blockparams.first || pBlock->nHeight < blockparams.second; });
    return (lower == vChain.end() ? nullptr : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
// COMMENT HOUSE: THE SKIP LIST, jumping backwards quickly.
// Walking back one block at a time over 900,000 blocks would be slow. So
// each index card also has a pskip pointer to a block further back. The
// height it jumps to is chosen by GetSkipHeight() using a binary trick
// (InvertLowestOne() clears the last 1 bit of a number). The jumps come in
// many sizes, from short to very long, a bit like express and local train
// stops. The developer comment says reaching a block 2^18 (about 262,000)
// blocks back takes at most 110 steps.
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

// COMMENT HOUSE: GetAncestor(): walk back to the given height. At each step,
// take the pskip shortcut if it does not overshoot (and is not worse than
// the next block's shortcut). Otherwise take one step back with pprev.
const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    const CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(height));
}

// COMMENT HOUSE: BuildSkip(): when a new index card is made, set its pskip
// shortcut, using GetAncestor() on its parent.
void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

// COMMENT HOUSE: GetBitsProof(): how much WORK a block with this nBits
// represents. With a target T, a random hash is at or below T about once
// every 2^256 / (T + 1) tries, so that is the expected number of hashes.
// 2^256 itself is too big to fit in 256 bits, so the developer comment
// shows a rearranged formula that gives the same answer. ~ flips every bit
// of a number.
arith_uint256 GetBitsProof(uint32_t bits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(bits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

// COMMENT HOUSE: Turns a difference in total work into TIME: roughly how many
// seconds of mining at today's difficulty that amount of work represents.
// Used for safety checks such as "is this chain close enough to the best
// one?".
int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * int64_t(r.GetLow64());
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
// COMMENT HOUSE: LastCommonAncestor(): where do two branches split? First
// bring the higher block down to the same height as the lower one. Then step
// both back together (using shortcuts when they match) until they land on
// the same block.
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    // First rewind to the last common height (the forking point cannot be past one of the two).
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }
    while (pa != pb) {
        // Jump back until pa and pb have a common "skip" ancestor.
        while (pa->pskip != pb->pskip) {
            // This logic relies on the property that equal-height blocks have equal-height skip
            // pointers.
            Assume(pa->nHeight == pb->nHeight);
            Assume(pa->pskip->nHeight == pb->pskip->nHeight);
            pa = pa->pskip;
            pb = pb->pskip;
        }
        // At this point, pa and pb are different, but have equal pskip. The forking point lies in
        // between pa/pb on the one end, and pa->pskip/pb->pskip on the other end.
        pa = pa->pprev;
        pb = pb->pprev;
    }
    return pa;
}
