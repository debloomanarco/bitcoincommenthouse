// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file BUILDS a new block, ready to be mined. It is where Phases 3
// and 4 meet: it picks valid transactions from the mempool, creates the
// coinbase transaction that pays the miner, and fills in the header.
// The result is a "block template": a complete block except for a
// winning nonce. Bitcoin Core does not search for the nonce itself. Mining
// hardware (special chips called ASICs) takes the template and does the
// billions of hashes per second needed to meet the target (see pow.cpp).
//
// Start with BlockAssembler::CreateNewBlock(), which does the whole job
// from top to bottom. addChunks() is how transactions are chosen.
#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/mining_args.h>
#include <node/mining_types.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <tinyformat.h>
#include <txgraph.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/log.h>
#include <util/result.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <versionbits.h>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace node {

// COMMENT HOUSE: GetMinimumTime(): the earliest timestamp the new block is
// allowed to have. Consensus requires it to be later than the "median
// time past" (the middle time of the previous 11 blocks). The extra rules
// (BIP 94 and BIP 54) stop miners from playing tricks with timestamps around
// difficulty adjustments to make mining artificially easy (a "timewarp
// attack").
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    // Account for the BIP54 Murch-Zawy rule on all networks: the last block of
    // a difficulty adjustment period may not be earlier than its first block.
    if (height % difficulty_adjustment_interval == difficulty_adjustment_interval - 1) {
        const int first_height{height - static_cast<int>(difficulty_adjustment_interval) + 1};
        const CBlockIndex* first_block{Assert(pindexPrev->GetAncestor(first_height))};
        min_time = std::max<int64_t>(min_time, first_block->GetBlockTime());
    }
    return min_time;
}

// COMMENT HOUSE: UpdateTime() sets the block's time to now, but never earlier
// than the minimum allowed above.
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

// COMMENT HOUSE: If the block's transactions change, the SegWit fingerprint
// in the coinbase (see GetWitnessCommitmentIndex() in consensus/validation.h)
// and the merkle root (consensus/merkle.cpp) must be recalculated. This
// function does both.
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

BlockAssembler::BlockAssembler(Chainstate& chainstate,
                               const CTxMemPool* mempool,
                               BlockCreateOptions options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_options{[&] {
          if (auto result{CheckMiningOptions(options, /*use_argnames=*/false)}; !result) {
              throw std::runtime_error(util::ErrorString(result).original);
          }
          return FlattenMiningOptions(std::move(options));
      }()}
{
}

void BlockAssembler::resetBlock()
{
    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockWeight = *Assert(m_options.block_reserved_weight);
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

// COMMENT HOUSE: CreateNewBlock(), building a block template, step by step:
//   1. Leave a space at the start for the coinbase transaction.
//   2. Pick the version (nVersion, which may signal upgrades, see
//      BIP9Deployment in consensus/params.h) and the time.
//   3. Fill the block with mempool transactions (addChunks()).
//   4. Build the coinbase transaction, which pays reward + fees.
//   5. Fill in the rest of the header: previous block hash, time, nBits.
//   6. Optionally test the whole block with the same validation rules every
//      node will use (TestBlockValidity()), but without proof-of-work.
std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction. It is skipped by the
    // getblocktemplate RPC and mining interface consumers must not use it.
    // COMMENT HOUSE: Step 1: a placeholder for the coinbase. It must be the first
    // transaction (CheckBlock() in validation.cpp requires that), but it can only
    // be built once the total fees are known, after step 3.
    pblock->vtx.emplace_back();

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    // COMMENT HOUSE: Step 2: the new block's height is one more than the current
    // tip of the chain (pindexPrev). The version may signal support for upgrades.
    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    // COMMENT HOUSE: Step 3: choose transactions from the mempool (see
    // addChunks() below).
    if (m_mempool) {
        LOCK(m_mempool->cs);
        m_mempool->StartBlockBuilding();
        addChunks();
        m_mempool->StopBlockBuilding();
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    // COMMENT HOUSE: Step 4: build the coinbase transaction. Its single input has
    // a "null" prevout, because it spends nothing and creates new coins.
    CMutableTransaction coinbaseTx;

    // Construct coinbase transaction struct in parallel
    CoinbaseTx& coinbase_tx{pblocktemplate->m_coinbase_tx};
    coinbase_tx.version = coinbaseTx.version;

    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
    coinbase_tx.sequence = coinbaseTx.vin[0].nSequence;

    // Add an output that spends the full coinbase reward.
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    // Block subsidy + fees
    // COMMENT HOUSE: The miner's pay: all the fees from the chosen transactions
    // plus the new coins allowed by GetBlockSubsidy() (validation.cpp). This is
    // exactly the limit ConnectBlock() checks ("bad-cb-amount").
    const CAmount block_reward{nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus())};
    coinbaseTx.vout[0].nValue = block_reward;
    coinbase_tx.block_reward_remaining = block_reward;

    // Start the coinbase scriptSig with the block height as required by BIP34.
    // Mining clients are expected to append extra data to this prefix, so
    // increasing its length would reduce the space they can use and may break
    // existing clients.
    // COMMENT HOUSE: BIP 34 requires the coinbase to begin with the block height.
    // That makes every coinbase transaction different, so two can never have the
    // same txid again.
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight;
    // Set script_sig_prefix here, so IPC mining clients are not affected by
    // the optional scriptSig padding below. They provide their own extraNonce,
    // and in a typical setup a pool name or realistic extraNonce already makes
    // the scriptSig long enough.
    coinbase_tx.script_sig_prefix = coinbaseTx.vin[0].scriptSig;
    if (nHeight <= 16) {
        // For blocks at heights <= 16, the BIP34-encoded height alone is only
        // one byte. Consensus requires coinbase scriptSigs to be at least two
        // bytes long (bad-cb-length), so an OP_0 is always appended at those
        // heights.
        coinbaseTx.vin[0].scriptSig << OP_0;
    }
    Assert(nHeight > 0);
    coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1);
    coinbase_tx.lock_time = coinbaseTx.nLockTime;

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    // COMMENT HOUSE: Add the SegWit fingerprint (witness commitment) to the
    // coinbase as an extra output.
    m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);

    const CTransactionRef& final_coinbase{pblock->vtx[0]};
    if (final_coinbase->HasWitness()) {
        const auto& witness_stack{final_coinbase->vin[0].scriptWitness.stack};
        // Consensus requires the coinbase witness stack to have exactly one
        // element of 32 bytes.
        Assert(witness_stack.size() == 1 && witness_stack[0].size() == 32);
        coinbase_tx.witness = uint256(witness_stack[0]);
    }
    if (const int witness_index = GetWitnessCommitmentIndex(*pblock); witness_index != NO_WITNESS_COMMITMENT) {
        Assert(witness_index >= 0 && static_cast<size_t>(witness_index) < final_coinbase->vout.size());
        coinbase_tx.required_outputs.push_back(final_coinbase->vout[witness_index]);
    }

    LogDebug(BCLog::MINING, "CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    // COMMENT HOUSE: Step 5: link to the previous block, set the time, and set the
    // difficulty for this height (GetNextWorkRequired() in pow.cpp). The nonce
    // starts at 0, and the miner will change it. The merkle root is filled in
    // later, once the final coinbase is known (see AddMerkleRootAndCoinbase()).
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;

    if (m_options.test_block_validity) {
        if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
            throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() chunks: %.2fms, validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start),
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

// COMMENT HOUSE: Would adding this group of transactions make the block too
// heavy (see weight in consensus/validation.h) or give it too many signature
// operations?
bool BlockAssembler::TestChunkBlockLimits(int64_t chunk_weight, int64_t chunk_sigops_cost) const
{
    // block_max_weight has been flattened before block assembly limit checks.
    Assert(m_options.block_max_weight);
    if (nBlockWeight + chunk_weight >= m_options.block_max_weight) {
        return false;
    }
    if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// COMMENT HOUSE: Are all these transactions free of time locks for this block
// (IsFinalTx() in consensus/tx_verify.cpp)?
bool BlockAssembler::TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const
{
    for (const auto tx : txs) {
        if (!IsFinalTx(tx.get().GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}

// COMMENT HOUSE: Adds one transaction to the block and updates the running
// totals: weight, number of transactions, signature operations and fees.
void BlockAssembler::AddToBlock(const CTxMemPoolEntry& entry)
{
    pblocktemplate->block.vtx.emplace_back(entry.GetSharedTx());
    pblocktemplate->vTxFees.push_back(entry.GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(entry.GetSigOpCost());
    nBlockWeight += entry.GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += entry.GetSigOpCost();
    nFees += entry.GetFee();

    if (*m_options.print_modified_fee) {
        LogInfo("fee rate %s txid %s\n",
                  CFeeRate(entry.GetModifiedFee(), entry.GetTxSize()).ToString(),
                  entry.GetTx().GetHash().ToString());
    }
}

// COMMENT HOUSE: addChunks(), choosing which transactions go in.
// Block space is limited, so miners want the transactions that pay the most
// fee per unit of space (the "fee rate"), not just the biggest fees. The
// mempool hands over transactions in "chunks", best fee rate first. A chunk
// is a group that must go in together. For example, if transaction B spends
// an output of transaction A, B cannot be included without A.
// For each chunk:
//   - if its fee rate is below the minimum, stop: all remaining ones are
//     worse;
//   - if it does not fit, skip it and try the next one;
//   - otherwise add it to the block.
// If the block is nearly full and many chunks in a row have not fit, it gives
// up to save time.
void BlockAssembler::addChunks()
{
    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> selected_transactions;
    selected_transactions.reserve(MAX_CLUSTER_COUNT_LIMIT);
    FeePerWeight chunk_feerate;

    // This fills selected_transactions
    chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
    FeePerVSize chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);

    while (selected_transactions.size() > 0) {
        // Check to see if min fee rate is still respected.
        if (ByRatio{chunk_feerate_vsize} < ByRatio{m_options.block_min_fee_rate->GetFeePerVSize()}) {
            // Everything else we might consider has a lower feerate
            return;
        }

        int64_t chunk_sig_ops = 0;
        int64_t chunk_weight = 0;
        for (const auto& tx : selected_transactions) {
            chunk_sig_ops += tx.get().GetSigOpCost();
            chunk_weight += tx.get().GetTxWeight();
        }

        // Check to see if this chunk will fit.
        if (!TestChunkBlockLimits(chunk_weight, chunk_sig_ops) || !TestChunkTransactions(selected_transactions)) {
            // This chunk won't fit, so we skip it and will try the next best one.
            m_mempool->SkipBuilderChunk();
            ++nConsecutiveFailed;

            // block_max_weight has been flattened before block assembly limit checks.
            Assert(m_options.block_max_weight);
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight +
                    BLOCK_FULL_ENOUGH_WEIGHT_DELTA > *m_options.block_max_weight) {
                // Give up if we're close to full and haven't succeeded in a while
                return;
            }
        } else {
            m_mempool->IncludeBuilderChunk();

            // This chunk will fit, so add it to the block.
            nConsecutiveFailed = 0;
            for (const auto& tx : selected_transactions) {
                AddToBlock(tx);
            }
            pblocktemplate->m_package_feerates.emplace_back(chunk_feerate_vsize);
        }

        selected_transactions.clear();
        chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
        chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);
    }
}

// COMMENT HOUSE: Used when a miner sends back a finished block: put in the
// final coinbase, version, time and nonce, then calculate the merkle root. The
// "already checked" flags are reset, because the block has changed and must
// be checked again.
void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Reset cached checks
    block.m_checked_witness_commitment = false;
    block.m_checked_merkle_root = false;
    block.fChecked = false;
}

} // namespace node
