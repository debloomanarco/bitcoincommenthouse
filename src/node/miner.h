// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// It announces the block-building code in node/miner.cpp. Read that file
// for the full step-by-step explanation of how a new block is put
// together. The two main pieces are CBlockTemplate (the result) and
// BlockAssembler (the builder).
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_NODE_MINER_H
#define BITCOIN_NODE_MINER_H

#include <consensus/amount.h>
#include <node/mining_types.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <threadsafety.h>
#include <txmempool.h>
#include <util/feefrac.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

class CBlockIndex;
class CChainParams;
class Chainstate;
class ChainstateManager;

namespace Consensus {
struct Params;
} // namespace Consensus
namespace node {

// COMMENT HOUSE: CBlockTemplate, a block ready to be mined. It has everything
// except a winning nonce, plus extra information for mining software: the
// fee and signature-operation cost of each transaction, the fee rate of each
// chunk chosen, and the coinbase details.
struct CBlockTemplate
{
    CBlock block;
    // Fees per transaction, not including coinbase transaction (unlike CBlock::vtx).
    std::vector<CAmount> vTxFees;
    // Sigops per transaction, not including coinbase transaction (unlike CBlock::vtx).
    std::vector<int64_t> vTxSigOpsCost;
    /* A vector of package fee rates, ordered by the sequence in which
     * packages are selected for inclusion in the block template.*/
    std::vector<FeePerVSize> m_package_feerates;
    /*
     * Template containing all coinbase transaction fields that are set by our
     * miner code.
     */
    CoinbaseTx m_coinbase_tx;
};

/** Generate a new block, without valid proof-of-work */
// COMMENT HOUSE: BlockAssembler, the builder. While it works, it keeps running
// totals (weight, number of transactions, signature operations, fees), so it
// knows when the block is full. CreateNewBlock() does the whole job, and the
// private helper functions are the steps it uses (see node/miner.cpp).
class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Information on the current status of the block
    uint64_t nBlockWeight;
    uint64_t nBlockTx;
    uint64_t nBlockSigOpsCost;
    CAmount nFees;

    // Chain context for the block
    int nHeight;
    int64_t m_lock_time_cutoff;

    const CChainParams& chainparams;
    const CTxMemPool* const m_mempool;
    Chainstate& m_chainstate;

public:
    explicit BlockAssembler(Chainstate& chainstate,
                            const CTxMemPool* mempool,
                            BlockCreateOptions create_options);

    /** Construct a new block template */
    std::unique_ptr<CBlockTemplate> CreateNewBlock();

    /** The number of transactions in the last assembled block (excluding coinbase transaction) */
    inline static std::optional<int64_t> m_last_block_num_txs{};
    /** The weight of the last assembled block (including reserved weight for block header, txs count and coinbase tx) */
    inline static std::optional<int64_t> m_last_block_weight{};

private:
    const BlockCreateOptions m_options;

    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(const CTxMemPoolEntry& entry);

    // Methods for how to add transactions to a block.
    /** Add transactions based on chunk feerate
      *
      * @pre BlockAssembler::m_mempool must not be nullptr
    */
    void addChunks() EXCLUSIVE_LOCKS_REQUIRED(m_mempool->cs);

    // helper functions for addChunks()
    /** Test if a new chunk would "fit" in the block */
    bool TestChunkBlockLimits(int64_t chunk_weight, int64_t chunk_sigops_cost) const;
    /** Perform locktime checks on each transaction in a chunk:
      * This check should always succeed, and is here
      * only as an extra check in case of a bug */
    bool TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const;
};

/**
 * Get the minimum time a miner should use in the next block. This always
 * accounts for the BIP94 timewarp rule, so does not necessarily reflect the
 * consensus limit.
 */
// COMMENT HOUSE: Helpers used while building and finishing a block: the
// earliest allowed timestamp, setting the time, and updating the witness
// commitment and merkle root after the transactions or coinbase change.
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, int64_t difficulty_adjustment_interval);

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

/** Update an old GenerateCoinbaseCommitment from CreateNewBlock after the block txs have changed */
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman);

/* Compute the block's merkle root, insert or replace the coinbase transaction and the merkle root into the block */
void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce);
} // namespace node

#endif // BITCOIN_NODE_MINER_H
