// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// PROOF-OF-WORK, the rules of mining.
// To add a block, a miner must find a block header whose hash (see
// CBlockHeader::GetHash() in primitives/block.cpp) is a number smaller than
// or equal to a TARGET. A hash is unpredictable, so the only way to find one
// is to try again and again, changing nNonce (and other parts of the block)
// each time. It is like rolling dice over and over until you get a very low
// number. Finding a valid hash takes huge effort, but anyone can check it
// with one hash. That is why it is called proof of WORK.
//   - A smaller target is harder to hit. "Difficulty" just describes how
//     small the target is.
//   - The target is stored in the header's nBits field in a compact form.
//   - Every 2016 blocks (about two weeks) the target is adjusted, so blocks
//     keep arriving every 10 minutes on average, no matter how many miners
//     join or leave.
//
// The functions:
//   - GetNextWorkRequired() / CalculateNextWorkRequired(): the next target.
//   - PermittedDifficultyTransition(): a quick check that a change in
//     difficulty is allowed.
//   - DeriveTarget() / CheckProofOfWork(): is this block's hash good enough?
// The big-number maths uses arith_uint256 (arith_uint256.h), a version of
// uint256 that supports + - * / and comparisons.
#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

// COMMENT HOUSE: GetNextWorkRequired() decides the nBits the block AFTER
// pindexLast must have.
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    // COMMENT HOUSE: Most of the time, the next block is not at an adjustment
    // point (its height is not a multiple of 2016). Then the difficulty stays
    // exactly the same as the last block's. The testnet rule inside is a special
    // exception for test networks only.
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // COMMENT HOUSE: At an adjustment point: find the first block of the 2016
    // that just finished, and pass its time to CalculateNextWorkRequired().
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

// COMMENT HOUSE: CalculateNextWorkRequired(), the difficulty adjustment.
// The idea is a simple ratio:
//     new target = old target x (actual time taken / time it should take)
// The last 2016 blocks should have taken two weeks. If they took only one
// week (blocks came too fast), the time ratio is 1/2, so the target halves and
// mining becomes twice as hard. If they took four weeks, the target doubles
// and mining becomes easier.
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    // COMMENT HOUSE: Limit the change: however fast or slow the last period was,
    // the time used is kept between half a week (two weeks / 4) and eight weeks
    // (two weeks x 4). So difficulty can change by at most 4 times in one
    // adjustment. This stops sudden huge jumps.
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    // COMMENT HOUSE: The ratio from above: multiply the old target by the actual
    // time, then divide by the expected time. The target may never become easier
    // than powLimit (see kernel/chainparams.cpp). GetCompact() packs the result
    // back into the nBits format.
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
// COMMENT HOUSE: PermittedDifficultyTransition() is a quick sanity check used
// when downloading block headers. Without knowing the exact block times, it
// checks that the difficulty did not change between adjustment points, and
// that at an adjustment point it changed by at most 4 times either way.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
// COMMENT HOUSE: "Fuzz testing" is automated testing with random data. During
// it, the real check is replaced with an easy one. In normal use, the real
// check, CheckProofOfWorkImpl(), always runs.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

// COMMENT HOUSE: DeriveTarget() unpacks nBits into the full target number.
// The compact form works like scientific notation (like writing 3 x 10^8
// instead of 300,000,000). The first byte is the size (exponent) and the
// other three bytes are the leading digits. For example, 0x1d00ffff (the
// genesis block's nBits) means 0x00ffff followed by 26 zero bytes.
// A target that is negative, zero, too large to fit, or easier than powLimit
// is rejected.
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

// COMMENT HOUSE: The actual proof-of-work test. Treat the block hash as a
// number: it must be less than or equal to the target. If it is, the miner
// did the work.
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
