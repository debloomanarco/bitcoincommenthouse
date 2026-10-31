// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// It announces the PROOF-OF-WORK functions, whose code is in pow.cpp. Read
// pow.cpp for the full explanation of mining, the target and difficulty.
#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <cstdint>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
// COMMENT HOUSE: DeriveTarget() unpacks the compact nBits number from the
// block header into the full 256-bit target.
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, uint256 pow_limit);

// COMMENT HOUSE: These two work out what nBits (difficulty) the NEXT block
// must use.
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
// COMMENT HOUSE: CheckProofOfWork() checks that a block's hash is at or below
// its target, which means the miner really did the work.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits);

#endif // BITCOIN_POW_H
